"""
Dependency Analyzer — cross-cutting Analyzer plugin.

Parses every recognised manifest, then (when threat intel is enabled and
the network is available) cross-references packages against the OSV feed
via the existing guardian.threat_intel collectors (24h disk cache).
Offline, it still reports the dependency inventory and flags packages
with no pinned version.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer
from guardian.dependencies.parsers import PARSERS, Dependency, parse_manifest

log = logging.getLogger(__name__)


#: Hard cap on OSV lookups per scan. A live query per dependency is fine
#: for a normal manifest (tens of packages); an enormous lockfile should
#: degrade to "checked the first N" rather than turn a scan into a
#: multi-minute network crawl.
MAX_OSV_LOOKUPS = 150


@register_analyzer
class DependencyAnalyzer:
    name = "dependencies"

    def __init__(self, enable_osv: bool = True):
        self.enable_osv = enable_osv

    def collect(self, files: Iterable[Path]) -> list[Dependency]:
        deps: list[Dependency] = []
        for fp in files:
            if fp.name in PARSERS:
                deps.extend(parse_manifest(fp))
        return deps

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        findings: list[Finding] = []
        deps = self.collect(files)
        for d in deps:
            if d.version is None:
                findings.append(Finding(
                    category="Unpinned Dependency", severity="Low", rule_id="DEP-001",
                    file=str(Path(d.manifest).name), line=1,
                    snippet=f"{d.name} ({d.ecosystem}) has no pinned version",
                    recommendation="Pin dependency versions for reproducible, auditable builds.",
                    confidence=0.9,
                ))
        if self.enable_osv and deps:
            findings.extend(self._osv_lookup(deps))
        return findings

    def _osv_lookup(self, deps: list[Dependency]) -> list[Finding]:
        """Cross-reference against the OSV.dev vulnerability feed via the
        existing threat-intel collector layer -- a real, free, no-API-key
        lookup (see guardian.threat_intel.collector.OSVCollector). Network
        failures, a missing package, or hitting the per-scan cap all
        degrade gracefully to the offline inventory-only behaviour; they
        never fail the scan."""
        try:
            from guardian.threat_intel.collector import OSVCollector  # existing v1 module
        except ImportError:
            log.warning("threat_intel collectors unavailable; skipping OSV lookup")
            return []
        findings: list[Finding] = []
        # Only pinned deps are checkable, and de-dupe repeats across
        # manifests (e.g. the same package pinned in requirements.txt and
        # backend/requirements.txt) so each unique package@version is only
        # looked up once per scan.
        seen: set[tuple[str, str, str]] = set()
        checkable: list[Dependency] = []
        for d in deps:
            if not d.version:
                continue
            key = (d.ecosystem, d.name, d.version)
            if key in seen:
                continue
            seen.add(key)
            checkable.append(d)
        if len(checkable) > MAX_OSV_LOOKUPS:
            log.info("dependency scan: capping OSV lookups at %d of %d unique packages",
                     MAX_OSV_LOOKUPS, len(checkable))
            checkable = checkable[:MAX_OSV_LOOKUPS]

        try:
            collector = OSVCollector()
            for d in checkable:
                try:
                    records = collector.fetch(d.name, d.version, ecosystem=d.ecosystem) or []
                except Exception as exc:  # noqa: BLE001 — one bad lookup must not skip the rest
                    log.debug("OSV lookup failed for %s@%s: %s", d.name, d.version, exc)
                    continue
                for rec in records:
                    findings.append(Finding(
                        category="Vulnerable Dependency", severity=rec.severity or "High",
                        rule_id=rec.cve_id or "OSV", file=str(Path(d.manifest).name), line=1,
                        snippet=f"{d.name}@{d.version}: {rec.description[:150]}",
                        recommendation="Upgrade to a patched version; see feed references.",
                        confidence=0.95,
                    ))
        except Exception as exc:  # noqa: BLE001 — network layer must never kill a scan
            log.warning("OSV lookup failed (%s); continuing offline", exc)
        return findings
