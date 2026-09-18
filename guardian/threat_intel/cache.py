"""
Threat Intelligence Engine — Cache
=====================================
Local disk-based JSON cache for CVE lookups.
Avoids hammering external APIs on every scan.
TTL defaults to 24 hours for CVE data (vulnerability status can change).

Design: file-per-query, keyed by (package, version) so entries expire
independently. The cache layer is stateless and injectable for testing.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from guardian.threat_intel.models import CVERecord, FeedSource

_DEFAULT_TTL_SECONDS = 86_400   # 24 hours
_CACHE_VERSION = "1"


def _cache_key(package: str, version: Optional[str]) -> str:
    v = version or "any"
    safe = f"{package}_{v}".replace("/", "_").replace("\\", "_").replace(":", "_")
    return f"ti_{safe}.json"


class ThreatIntelCache:
    """
    Write-through disk cache. All reads go through `get`; writes through `put`.
    Set `ttl_seconds=0` to disable expiry (useful for offline/air-gapped mode).
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ):
        self._dir = Path(cache_dir) if cache_dir else Path.home() / ".ai_code_guardian" / "ti_cache"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl_seconds

    def _path(self, package: str, version: Optional[str]) -> Path:
        return self._dir / _cache_key(package, version)

    def get(self, package: str, version: Optional[str] = None) -> Optional[list[CVERecord]]:
        path = self._path(package, version)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if data.get("version") != _CACHE_VERSION:
                return None
            if self._ttl > 0 and time.time() - data.get("fetched_at", 0) > self._ttl:
                return None   # stale
            return [self._deserialize(r) for r in data.get("cves", [])]
        except Exception:
            return None

    def put(self, package: str, version: Optional[str], cves: list[CVERecord]) -> None:
        path = self._path(package, version)
        try:
            payload = {
                "version": _CACHE_VERSION,
                "fetched_at": time.time(),
                "package": package,
                "version_pin": version,
                "cves": [c.to_dict() for c in cves],
            }
            path.write_text(json.dumps(payload, default=str))
        except Exception:
            pass

    def invalidate(self, package: str, version: Optional[str] = None) -> None:
        path = self._path(package, version)
        if path.exists():
            path.unlink(missing_ok=True)

    def clear_all(self) -> int:
        count = 0
        for f in self._dir.glob("ti_*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count

    @staticmethod
    def _deserialize(record: dict) -> CVERecord:
        # Reconstruct FeedSource enum from string
        source_str = record.pop("source", "NVD")
        try:
            source = FeedSource(source_str)
        except ValueError:
            source = FeedSource.MANUAL
        return CVERecord(source=source, **{k: v for k, v in record.items() if k != "source"})
