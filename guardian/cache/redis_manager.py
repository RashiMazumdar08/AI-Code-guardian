"""
Redis Manager
=============
Handles Redis connection pooling, repo state hashing, and generic caching
for the UST and other expensive computations.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency
    redis = None  # Caching degrades to a no-op; it must never crash the caller.

log = logging.getLogger(__name__)


class RedisManager:
    """Manages Redis connections and repository hashing."""

    _pool: Optional[redis.ConnectionPool] = None

    def __init__(self, url: Optional[str] = None):
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.enabled = False
        self.client = None
        if redis is None:
            log.warning(
                "The 'redis' package is not installed. Caching disabled; "
                "callers must fall back to computing results directly."
            )
            return
        try:
            if RedisManager._pool is None:
                RedisManager._pool = redis.ConnectionPool.from_url(
                    self.url,
                    socket_connect_timeout=0.5,
                    socket_timeout=1.0,
                    socket_keepalive=True,
                    decode_responses=True
                )
            self.client = redis.Redis(connection_pool=RedisManager._pool)
            self.client.ping()
            self.enabled = True
        except Exception as e:
            log.warning("Redis is not available at %s (%s). Caching disabled.", self.url, e)
            self.enabled = False

    _mem_cache: dict[str, tuple[float, str]] = {}

    def get_json(self, key: str) -> Optional[Any]:
        if self.enabled:
            try:
                val = self.client.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                log.debug("Redis GET failed for %s: %s", key, e)
        item = RedisManager._mem_cache.get(key)
        if item:
            exp, val_str = item
            if time.time() < exp:
                return json.loads(val_str)
            RedisManager._mem_cache.pop(key, None)
        return None

    def set_json(self, key: str, value: Any, ttl: int = 86400) -> bool:
        val_str = json.dumps(value)
        if self.enabled:
            try:
                self.client.set(key, val_str, ex=ttl)
            except Exception as e:
                log.debug("Redis SET failed for %s: %s", key, e)
        RedisManager._mem_cache[key] = (time.time() + ttl, val_str)
        return True

    @staticmethod
    def hash_file_content(content: str | bytes) -> str:
        """Stable SHA-256 of one file's source bytes -- the basis of the
        per-file UST cache in guardian/ust/builder.py. Two files hash
        identically whenever their CONTENT is identical, regardless of
        path, mtime, or which repository they live in, so a rename or an
        unrelated edit elsewhere in the repo no longer invalidates this
        file's cached parse. Deliberately independent of
        generate_repo_hash() below, which addresses the whole repository
        as one unit and is kept for any caller that still wants that."""
        if isinstance(content, str):
            content = content.encode("utf-8", errors="ignore")
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def generate_repo_hash(repo_root: Path | str) -> str:
        """
        Generates a deterministic hash for the repository state.
        Tries git rev-parse HEAD first, then falls back to hashing files.
        """
        repo_path = Path(repo_root).resolve()
        
        # 1. Try Git commit hash
        try:
            git_hash = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], 
                cwd=str(repo_path),
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            # If dirty, fallback
            status = subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=str(repo_path),
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            if not status:
                return f"git:{git_hash}"
        except Exception:
            pass

        # 2. Fallback to file contents / timestamps
        hasher = hashlib.sha256()
        try:
            for root, _, files in os.walk(repo_path):
                # Skip common ignored dirs
                if any(x in root for x in [".git", "node_modules", "venv", "__pycache__", ".acg_workspaces"]):
                    continue
                for f in sorted(files):
                    file_path = Path(root) / f
                    try:
                        stat = file_path.stat()
                        hasher.update(str(file_path.relative_to(repo_path)).encode('utf-8'))
                        hasher.update(str(stat.st_mtime).encode('utf-8'))
                        hasher.update(str(stat.st_size).encode('utf-8'))
                    except Exception:
                        pass
        except Exception:
            # Absolute worst case, just hash the path
            hasher.update(str(repo_path).encode('utf-8'))
            
        return f"files:{hasher.hexdigest()}"
