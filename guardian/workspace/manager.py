"""
AI Code Guardian v3 — Repository Workspace Manager
===================================================
Manages local repositories, ZIP archive extractions, public GitHub git cloning,
scan history persistence, and unique repository IDs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.workspace")


class RepositoryManager:
    """Manages workspace repositories, extractions, cloning, and history."""

    def __init__(self, base_workspace_dir: Optional[Path] = None) -> None:
        self.base_dir = base_workspace_dir or Path(os.getcwd()) / ".acg_workspaces"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.base_dir / "history.json"
        self._ensure_history()

    def _ensure_history(self) -> None:
        if not self.history_file.exists():
            self._write_history({})

    def _read_history(self) -> Dict[str, Any]:
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_history(self, history: Dict[str, Any]) -> None:
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to write workspace history: {e}")

    def generate_repo_id(self, repo_path_or_url: str) -> str:
        """Generates deterministic repository ID based on path or URL."""
        clean_str = str(Path(repo_path_or_url).resolve()) if os.path.exists(repo_path_or_url) else str(repo_path_or_url)
        return "repo-" + hashlib.sha256(clean_str.encode("utf-8")).hexdigest()[:12]

    def register_local_repository(self, local_path: str, domain: str = "general", criticality: str = "NORMAL") -> Dict[str, Any]:
        """Registers an existing local folder as a workspace repository."""
        path_obj = Path(local_path).resolve()
        if not path_obj.exists() or not path_obj.is_dir():
            raise ValueError(f"Local repository path does not exist or is not a directory: {local_path}")

        repo_id = self.generate_repo_id(str(path_obj))
        size_bytes = sum(f.stat().st_size for f in path_obj.rglob("*") if f.is_file() and not any(part.startswith(".") for part in f.parts))

        info = {
            "repository_id": repo_id,
            "repo_name": path_obj.name or "root",
            "repo_path": str(path_obj),
            "source_type": "LOCAL",
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "business_domain": domain,
            "criticality": criticality,
            "registered_at": os.stat(path_obj).st_mtime,
            "last_scan_time": None,
        }

        history = self._read_history()
        history[repo_id] = info
        self._write_history(history)
        return info

    def extract_zip_repository(self, zip_file_bytes_or_path: Any, filename: str = "uploaded.zip") -> Dict[str, Any]:
        """Extracts an uploaded ZIP archive into a managed workspace sandbox directory."""
        temp_zip_path = self.base_dir / filename
        if isinstance(zip_file_bytes_or_path, (bytes, bytearray)):
            with open(temp_zip_path, "wb") as f:
                f.write(zip_file_bytes_or_path)
        elif hasattr(zip_file_bytes_or_path, "read"):
            with open(temp_zip_path, "wb") as f:
                f.write(zip_file_bytes_or_path.read())
        elif isinstance(zip_file_bytes_or_path, (str, Path)) and os.path.exists(zip_file_bytes_or_path):
            shutil.copy(str(zip_file_bytes_or_path), str(temp_zip_path))
        else:
            raise ValueError("Invalid ZIP file payload.")

        repo_id = "repo-zip-" + hashlib.sha256(filename.encode("utf-8") + os.urandom(4)).hexdigest()[:10]
        extract_dir = self.base_dir / repo_id
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(temp_zip_path, "r") as zf:
            zf.extractall(extract_dir)

        if temp_zip_path.exists():
            temp_zip_path.unlink()

        # If zip contained single root directory, unnest it
        children = [c for c in extract_dir.iterdir() if c.name != "__MACOSX"]
        if len(children) == 1 and children[0].is_dir():
            target_path = children[0]
        else:
            target_path = extract_dir

        return self.register_local_repository(str(target_path))

    def clone_github_repository(self, github_url: str) -> Dict[str, Any]:
        """Clones a public GitHub repository into the workspace directory."""
        clean_url = github_url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://") or clean_url.startswith("git@")):
            raise ValueError("Invalid GitHub repository URL.")

        repo_name = clean_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_id = "repo-git-" + hashlib.sha256(clean_url.encode("utf-8")).hexdigest()[:10]
        target_dir = self.base_dir / repo_id

        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)

        import subprocess
        res = subprocess.run(["git", "clone", "--depth", "1", clean_url, str(target_dir)], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Git clone failed: {res.stderr}")

        return self.register_local_repository(str(target_dir))

    def list_history(self) -> List[Dict[str, Any]]:
        """Returns list of registered repository history objects."""
        history = self._read_history()
        return list(history.values())

    def get_repository_info(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves history info for a specific repository_id."""
        history = self._read_history()
        return history.get(repo_id)
