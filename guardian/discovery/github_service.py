"""
GitHub Repository Service
=========================
Parses GitHub repository URLs/slugs and fetches source code via shallow git clone
or GitHub REST API Zipball download. Supports public and private repositories.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
import io
import logging
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger(__name__)

# Patterns matching GitHub URLs and slugs
_GITHUB_URL_PAT = re.compile(
    r'^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)'
    r'(?:/(?:tree|blob)/([A-Za-z0-9_.\-/]+))?(?:\.git)?/?$'
    # trailing /? -- without it, is_github_url("https://github.com/org/repo/")
    # (bare repo URL, trailing slash, no tree/blob suffix) failed to match and
    # the input was misdetected as a local path. parse_github_url() already
    # tolerated this via rstrip('/'); the detection regex didn't.
)
_GITHUB_SLUG_PAT = re.compile(r'^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)$')


def is_github_url(target: str) -> bool:
    """Return True if target looks like a GitHub URL or owner/repo slug."""
    if not isinstance(target, str):
        return False
    s = target.strip()
    if s.startswith("http://") or s.startswith("https://") or "github.com" in s:
        return bool(_GITHUB_URL_PAT.match(s))
    # Exclude local directory paths (e.g. ./foo, /bar, C:\foo)
    if os.path.exists(s) or s.startswith(".") or s.startswith("/") or "\\" in s:
        return False
    return bool(_GITHUB_SLUG_PAT.match(s))


def parse_github_url(target: str) -> Tuple[str, str, Optional[str]]:
    """Extract (owner, repo, ref) from a GitHub URL or slug."""
    s = target.strip().rstrip('/')
    m = _GITHUB_URL_PAT.match(s)
    if m:
        owner, repo, ref = m.group(1), m.group(2).removesuffix(".git"), m.group(3)
        if ref:
            ref = ref.rstrip('/')
        return owner, repo, ref
    m2 = _GITHUB_SLUG_PAT.match(s)
    if m2:
        return m2.group(1), m2.group(2).removesuffix(".git"), None
    raise ValueError(f"Invalid GitHub URL or slug: {target}")


class GitHubService:
    """Service for cloning and downloading GitHub repositories."""

    def __init__(self, work_dir: Optional[Path] = None) -> None:
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "guardian_github_repos"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        # Diagnostic detail from the most recent attempt of each fetch
        # strategy — previously both failure paths swallowed the real
        # reason (git not on PATH, HTTP 404, timeout, ...) and only ever
        # surfaced a generic "check URL/network/token" message.
        self._last_clone_error: Optional[str] = None
        self._last_zipball_error: Optional[str] = None

    def fetch_repository(self, target: str, token: Optional[str] = None) -> Path:
        """Fetch repository from GitHub into a local directory and return Path."""
        owner, repo, ref = parse_github_url(target)
        token = token or os.environ.get("GITHUB_TOKEN")

        dest_dir = self.work_dir / f"{owner}_{repo}_{ref or 'default'}"
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        dest_dir.mkdir(parents=True, exist_ok=True)

        self._last_clone_error = None
        self._last_zipball_error = None

        # 1. Try shallow git clone
        if self._git_clone(owner, repo, ref, dest_dir, token):
            log.info("Successfully cloned %s/%s via git", owner, repo)
            return dest_dir

        # 2. Fallback: HTTP Zipball download. When no explicit ref was
        # given, resolve the repository's *actual* default branch instead
        # of assuming "main" — plenty of repos (older ones especially)
        # still default to "master" or something else, and the zipball
        # endpoint 404s on the wrong branch name.
        resolved_ref = ref or self._resolve_default_branch(owner, repo, token) or "main"
        if self._download_zipball(owner, repo, resolved_ref, dest_dir, token):
            log.info("Successfully downloaded %s/%s via HTTP zipball (%s)", owner, repo, resolved_ref)
            return dest_dir

        details = []
        if self._last_clone_error:
            details.append(f"git clone failed: {self._last_clone_error}")
        if self._last_zipball_error:
            details.append(f"zipball download failed ({resolved_ref}): {self._last_zipball_error}")
        detail_str = " | ".join(details) if details else "no diagnostic detail captured"
        log.error("Failed to fetch %s/%s: %s", owner, repo, detail_str)
        raise RuntimeError(
            f"Failed to fetch GitHub repository {owner}/{repo}. "
            f"Check URL, network, or GITHUB_TOKEN. ({detail_str})")

    def _git_clone(self, owner: str, repo: str, ref: Optional[str], dest_dir: Path, token: Optional[str]) -> bool:
        if token:
            clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
        else:
            clone_url = f"https://github.com/{owner}/{repo}.git"

        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd.extend(["--branch", ref])
        cmd.extend([clone_url, str(dest_dir)])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0 and any(dest_dir.iterdir()):
                return True
            self._last_clone_error = (
                (res.stderr or res.stdout or f"git exited with code {res.returncode}")
                .strip().splitlines()[-1] if (res.stderr or res.stdout) else f"git exited with code {res.returncode}"
            )[:300]
            return False
        except FileNotFoundError:
            self._last_clone_error = "git executable not found on PATH"
            return False
        except subprocess.TimeoutExpired:
            self._last_clone_error = "git clone timed out after 120s"
            return False
        except (subprocess.SubprocessError, OSError) as exc:
            self._last_clone_error = str(exc)
            return False

    def _download_zipball(self, owner: str, repo: str, ref: Optional[str], dest_dir: Path, token: Optional[str]) -> bool:
        ref_str = ref or "main"
        url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref_str}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AICodeGuardian/2.0")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(dest_dir)

            # Zipball extracts with a root wrapper dir (e.g. owner-repo-sha/); flatten if needed
            subdirs = [p for p in dest_dir.iterdir() if p.is_dir()]
            if len(subdirs) == 1 and not (dest_dir / "README.md").exists():
                wrapper = subdirs[0]
                for item in wrapper.iterdir():
                    shutil.move(str(item), str(dest_dir / item.name))
                wrapper.rmdir()
            return True
        except Exception as e:
            self._last_zipball_error = str(e)
            log.warning("Zipball download failed for %s/%s (ref=%s): %s", owner, repo, ref_str, e)
            return False

    def _resolve_default_branch(self, owner: str, repo: str, token: Optional[str]) -> Optional[str]:
        """Best-effort lookup of the repository's actual default branch
        (e.g. 'master' vs 'main'), so the zipball fallback targets the
        right ref instead of assuming every repo uses 'main'. Returns
        None on any failure — the caller falls back to "main"."""
        import json as _json

        url = f"https://api.github.com/repos/{owner}/{repo}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AICodeGuardian/2.0")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read())
            return data.get("default_branch")
        except Exception as exc:  # noqa: BLE001 — best-effort only
            log.debug("Could not resolve default branch for %s/%s: %s", owner, repo, exc)
            return None

    def cleanup(self) -> None:
        """Remove temporary fetched repositories."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
