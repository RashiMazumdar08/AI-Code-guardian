"""
Files API Endpoint
==================
Provides repository file tree and raw file content retrieval for the IDE Code Viewer.

2026-09-15 fix -- unbounded synchronous tree walk
--------------------------------------------------
`GET /files/tree` used to call `build_file_tree()` directly inside the
`async def` route with no `await`. That makes the whole recursive walk run
synchronously on the event loop thread, blocking every other request the
backend is handling until it finishes. On top of that, the walk only
skipped a small hardcoded set of directory names
({".git", ".venv", "__pycache__", "node_modules", ".next"}) -- far smaller
than the scanner's own guardian.config.DEFAULT_IGNORE_DIRS (which also
skips "dist", "build", ".pytest_cache", ".mypy_cache", ".tox", "coverage",
"vendor", ".turbo", ".cache", etc.) -- and had no symlink-cycle guard at
all, unlike guardian/discovery/file_walker.py's FileWalker.walk(), which
this endpoint doesn't reuse. On a repository with any of those bloat
directories present, or a symlink cycle, this made `/files/tree` far
slower than the scan itself (which DOES skip them), and a real symlink
loop would recurse forever.

Fixed by: (1) reusing the scanner's own ignore list so the IDE tree skips
exactly what the scan itself skipped, (2) adding the same realpath-based
cycle guard FileWalker uses, and (3) running the synchronous walk in a
worker thread via `run_in_threadpool` so it can't block the event loop
even on a very large repository.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from backend.app.api.v1.scans import _SCANS_STORE
from guardian.config import DEFAULT_IGNORE_DIRS

router = APIRouter(prefix="/files", tags=["files"])


def _is_ignored(name: str) -> bool:
    return (name in DEFAULT_IGNORE_DIRS
            or name.startswith(".git")
            or name.startswith(".venv")
            or name.startswith("venv"))


def build_file_tree(repo_root: Path, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Build a lookup for vulnerable files
    vuln_map = {}
    for f in findings:
        file_path = f.get("file", "").replace("\\", "/")
        if not file_path:
            continue
        if file_path not in vuln_map:
            vuln_map[file_path] = {"count": 0, "max_severity": "INFO"}
        vuln_map[file_path]["count"] += 1

        # Determine max severity
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        curr_sev = f.get("severity", "INFO").upper()
        max_sev = vuln_map[file_path]["max_severity"]
        if severity_order.get(curr_sev, 0) > severity_order.get(max_sev, 0):
            vuln_map[file_path]["max_severity"] = curr_sev

    # Cycle guard mirroring FileWalker.walk(): never re-enter a directory
    # whose resolved real path we've already visited (symlink loops).
    seen_real: set[str] = set()

    def get_node(path: Path) -> Dict[str, Any]:
        rel_path = path.relative_to(repo_root).as_posix()
        node = {
            "name": path.name,
            "path": rel_path,
            "type": "directory" if path.is_dir() else "file",
            "has_vulnerabilities": False,
            "vulnerability_count": 0,
            "max_severity": None,
        }

        if path.is_dir():
            real = os.path.realpath(path)
            if real in seen_real:
                node["children"] = []
                return node
            seen_real.add(real)

            children = []
            dir_vuln_count = 0
            dir_max_sev = "INFO"
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

            for child in path.iterdir():
                # Skip build/cache/dependency bloat -- the same set the
                # scanner itself skips (guardian.config.DEFAULT_IGNORE_DIRS),
                # not just the five names this endpoint used to hardcode.
                if _is_ignored(child.name):
                    continue
                child_node = get_node(child)
                children.append(child_node)

                if child_node["has_vulnerabilities"]:
                    node["has_vulnerabilities"] = True
                    dir_vuln_count += child_node["vulnerability_count"]
                    if severity_order.get(child_node["max_severity"], 0) > severity_order.get(dir_max_sev, 0):
                        dir_max_sev = child_node["max_severity"]

            node["children"] = sorted(children, key=lambda x: (x["type"] != "directory", x["name"].lower()))
            node["vulnerability_count"] = dir_vuln_count
            node["max_severity"] = dir_max_sev if node["has_vulnerabilities"] else None
        else:
            if rel_path in vuln_map:
                node["has_vulnerabilities"] = True
                node["vulnerability_count"] = vuln_map[rel_path]["count"]
                node["max_severity"] = vuln_map[rel_path]["max_severity"]

        return node

    return get_node(repo_root)


@router.get("/tree")
async def get_file_tree(scan_id: str = Query(..., description="ID of the scan")):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan_data = _SCANS_STORE[scan_id]
    target_dir = scan_data.get("target") or scan_data.get("scan", {}).get("target") or scan_data.get("repository", {}).get("root")
    if not target_dir or not os.path.exists(target_dir):
        # Fallback to empty tree if repo root is no longer available
        return {"name": "root", "path": "", "type": "directory", "children": []}

    findings = scan_data.get("scan", {}).get("findings", [])
    # Run the (potentially large) synchronous walk in a worker thread so it
    # never blocks the event loop -- see module docstring.
    tree = await run_in_threadpool(build_file_tree, Path(target_dir), findings)
    return tree


@router.get("/content")
async def get_file_content(
    scan_id: str = Query(..., description="ID of the scan"),
    path: str = Query(..., description="Relative file path")
):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan_data = _SCANS_STORE[scan_id]
    target_dir = scan_data.get("target") or scan_data.get("scan", {}).get("target") or scan_data.get("repository", {}).get("root")
    if not target_dir or not os.path.exists(target_dir):
        raise HTTPException(status_code=404, detail="Repository root not found.")

    repo_root = Path(target_dir).resolve()
    file_path = (repo_root / path).resolve()

    if not str(file_path).startswith(str(repo_root)):
        raise HTTPException(status_code=403, detail="Access denied: Path outside repository boundary.")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File '{path}' not found.")

    try:
        content = file_path.read_text(encoding="utf-8")
        return {"content": content}
    except UnicodeDecodeError:
        return {"content": "// Binary file or unsupported encoding"}
