"""
Threat Intelligence Engine — Collector
=========================================
Fetches raw CVE data from external threat feeds.

Repository pattern: each feed is a class implementing `BaseFeedCollector`.
The ThreatIntelligenceCollector orchestrates them and stores results
via the cache layer. Swapping feeds (or mocking them in tests) requires
only implementing the interface.

Network dependencies are isolated here. No other module makes HTTP calls.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from guardian.threat_intel.models import CVERecord, FeedMetadata, FeedSource

# ---------------------------------------------------------------------------
# Base interface
# ---------------------------------------------------------------------------

class BaseFeedCollector(ABC):
    """
    Implement this interface to add a new threat feed.
    The ThreatIntelligenceCollector does not know which feeds are active —
    it iterates over whatever list is injected at construction time.
    """
    source: FeedSource

    @abstractmethod
    def fetch(self, package: str, version: str | None = None) -> list[CVERecord]:
        """Fetch CVEs related to `package` (and optionally `version`)."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the feed endpoint is reachable."""
        ...


# ---------------------------------------------------------------------------
# NVD collector (NIST National Vulnerability Database)
# ---------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _nvd_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

def _parse_nvd_item(item: dict) -> CVERecord | None:
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        # CVSS v3.1 preferred, fall back to v2
        metrics = cve.get("metrics", {})
        cvss_score, cvss_vector = 0.0, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_score = float(m.get("baseScore", 0))
                cvss_vector = m.get("vectorString", "")
                break
        # CWE
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = [
            d["value"] for w in weaknesses
            for d in w.get("description", []) if d.get("value", "").startswith("CWE-")
        ]
        published = cve.get("published", "")[:10]
        modified = cve.get("lastModified", "")[:10]
        configs = cve.get("configurations", [])
        affected = [
            n.get("cpeMatch", [{}])[0].get("criteria", "")
            for c in configs for n in c.get("nodes", []) if n.get("cpeMatch")
        ][:5]
        refs = [r.get("url", "") for r in cve.get("references", [])][:5]
        return CVERecord(
            cve_id=cve_id,
            description=desc[:400],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            epss_score=-1,  # NVD does not provide EPSS; enriched later if EPSS feed active
            severity=_nvd_severity(cvss_score),
            published=published,
            modified=modified,
            cwe_ids=cwe_ids,
            affected_packages=affected,
            source=FeedSource.NVD,
            references=refs,
        )
    except Exception:
        return None


class NVDCollector(BaseFeedCollector):
    source = FeedSource.NVD

    def __init__(self, timeout: int = 10):
        self._timeout = timeout

    def fetch(self, package: str, version: str | None = None) -> list[CVERecord]:
        keyword = package if not version else f"{package} {version}"
        url = f"{_NVD_API}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=20"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AICodeGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            return []
        items = data.get("vulnerabilities", [])
        return [r for r in (_parse_nvd_item(i) for i in items) if r is not None]

    def health_check(self) -> bool:
        try:
            req = urllib.request.Request(_NVD_API + "?resultsPerPage=1",
                                          headers={"User-Agent": "AICodeGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# CISA KEV collector (Known Exploited Vulnerabilities catalog)
# ---------------------------------------------------------------------------

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector(BaseFeedCollector):
    """
    CISA KEV provides a JSON catalog of actively exploited CVEs.
    We fetch the entire catalog (small, ~1MB) and filter by package keyword.
    """
    source = FeedSource.CISA_KEV

    def __init__(self, timeout: int = 15):
        self._timeout = timeout
        self._catalog: list[dict] = []
        self._fetched_at: float = 0.0

    def _ensure_catalog(self):
        # Refresh catalog at most once per hour
        if time.time() - self._fetched_at < 3600 and self._catalog:
            return
        try:
            req = urllib.request.Request(_CISA_KEV_URL, headers={"User-Agent": "AICodeGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
            self._catalog = data.get("vulnerabilities", [])
            self._fetched_at = time.time()
        except Exception:
            pass

    def fetch(self, package: str, version: str | None = None) -> list[CVERecord]:
        self._ensure_catalog()
        keyword = package.lower()
        results = []
        for item in self._catalog:
            if keyword not in item.get("product", "").lower() and \
               keyword not in item.get("vendorProject", "").lower():
                continue
            results.append(CVERecord(
                cve_id=item.get("cveID", ""),
                description=item.get("shortDescription", "")[:400],
                cvss_score=0.0,   # CISA KEV doesn't provide CVSS scores
                cvss_vector="",
                epss_score=-1,
                severity="High",  # All KEV entries are actively exploited → High minimum
                published=item.get("dateAdded", ""),
                modified=item.get("dateAdded", ""),
                known_exploited=True,
                source=FeedSource.CISA_KEV,
            ))
        return results

    def health_check(self) -> bool:
        try:
            req = urllib.request.Request(_CISA_KEV_URL, headers={"User-Agent": "AICodeGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# OSV collector (Open Source Vulnerabilities)
# ---------------------------------------------------------------------------

_OSV_API = "https://api.osv.dev/v1/query"


# OSV's ecosystem strings for the manifests guardian.dependencies.parsers
# already recognises (PyPI/npm/Maven/Go). Extend this alongside any new
# parser -- an unmapped ecosystem is still sent as-is, OSV just won't
# scope the query to it as tightly.
_OSV_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go",
}

# GitHub Security Advisories (OSV's most common source for database_specific
# .severity) use "MODERATE", not "Medium" -- and are otherwise all-caps.
# Map onto the app's canonical Severity buckets (guardian.core.models
# .Severity) so these findings sort, filter, and score exactly like every
# other finding instead of silently missing every severity-keyed lookup.
_OSV_SEVERITY_MAP = {
    "CRITICAL": "Critical", "HIGH": "High",
    "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low",
}


def _osv_severity(vuln: dict[str, Any]) -> str:
    raw = vuln.get("database_specific", {}).get("severity")
    if raw:
        mapped = _OSV_SEVERITY_MAP.get(str(raw).upper())
        if mapped:
            return mapped
    # Some ecosystems (PyPI in particular) carry a CVSS vector instead of a
    # database_specific label. Pull a base score out of it if we can.
    for entry in vuln.get("severity", []) or []:
        vector = str(entry.get("score", ""))
        score = _cvss_base_from_vector(vector)
        if score is not None:
            return _nvd_severity(score)
    return "Medium"


def _cvss_base_from_vector(vector: str) -> float | None:
    """Best-effort CVSS v3 base score from a vector string like
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'. OSV does not always
    include a numeric score alongside the vector, so this estimates
    severity from Confidentiality/Integrity/Availability + Attack Vector
    impact rather than implementing the full CVSS formula -- good enough
    to bucket into Critical/High/Medium/Low, not meant to be authoritative."""
    if "CVSS:3" not in vector:
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    impact_high = sum(1 for k in ("C", "I", "A") if parts.get(k) == "H")
    if parts.get("AV") == "N" and impact_high >= 2:
        return 9.0
    if impact_high >= 2:
        return 7.5
    if impact_high == 1:
        return 5.0
    return 3.0


class OSVCollector(BaseFeedCollector):
    source = FeedSource.OSV

    def __init__(self, timeout: int = 10):
        self._timeout = timeout

    def fetch(self, package: str, version: str | None = None,
              ecosystem: str | None = None) -> list[CVERecord]:
        pkg: dict[str, Any] = {"name": package}
        osv_ecosystem = _OSV_ECOSYSTEM.get((ecosystem or "").lower(), ecosystem)
        if osv_ecosystem:
            pkg["ecosystem"] = osv_ecosystem
        payload: dict[str, Any] = {"package": pkg}
        if version:
            payload["version"] = version
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            _OSV_API, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "AICodeGuardian/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            return []
        results = []
        for vuln in data.get("vulns", []):
            cve_aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
            cve_id = cve_aliases[0] if cve_aliases else vuln.get("id", "")
            results.append(CVERecord(
                cve_id=cve_id,
                description=vuln.get("summary", "")[:400],
                cvss_score=0.0,
                cvss_vector="",
                epss_score=-1,
                severity=_osv_severity(vuln),
                published=vuln.get("published", "")[:10],
                modified=vuln.get("modified", "")[:10],
                source=FeedSource.OSV,
                references=[r.get("url", "") for r in vuln.get("references", [])][:5],
            ))
        return results

    def health_check(self) -> bool:
        try:
            body = json.dumps({"package": {"name": "test"}}).encode()
            req = urllib.request.Request(
                _OSV_API, data=body,
                headers={"Content-Type": "application/json", "User-Agent": "AICodeGuardian/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ThreatIntelligenceCollector:
    """
    Aggregates results from multiple feed collectors.
    Deduplicates CVEs by ID across feeds.
    """

    def __init__(self, collectors: list[BaseFeedCollector] | None = None):
        # Default: NVD + CISA KEV + OSV
        self._collectors = collectors or [NVDCollector(), CISAKEVCollector(), OSVCollector()]

    def collect(self, package: str, version: str | None = None) -> list[CVERecord]:
        seen: dict[str, CVERecord] = {}
        for collector in self._collectors:
            try:
                for cve in collector.fetch(package, version):
                    if not cve.cve_id:
                        continue
                    # Merge: prefer record with higher CVSS score
                    existing = seen.get(cve.cve_id)
                    if existing is None or cve.cvss_score > existing.cvss_score:
                        # Preserve known_exploited flag from any source
                        if existing and existing.known_exploited:
                            cve.known_exploited = True
                        seen[cve.cve_id] = cve
            except Exception:
                continue
        return list(seen.values())

    def health(self) -> dict[str, bool]:
        return {c.source.value: c.health_check() for c in self._collectors}
