"""
Threat Intelligence Engine — Data Models
==========================================
Stable types for CVE data, feed records, and the ThreatContext objects
returned to callers. Designed so feed adapters (NVD, CISA, OSV, GitHub)
can be swapped without changing these models or downstream consumers.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class FeedSource(str, Enum):
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"
    GITHUB_ADVISORY = "GitHub_Advisory"
    OSV = "OSV"
    MANUAL = "Manual"


@dataclass
class CVERecord:
    """
    Normalised representation of a single CVE across all feed sources.
    """
    cve_id: str
    description: str
    cvss_score: float           # CVSS base score (0.0 – 10.0)
    cvss_vector: str            # e.g. "CVSS:3.1/AV:N/AC:L/..."
    epss_score: float           # EPSS probability (0.0 – 1.0), -1 if unknown
    severity: str               # Critical / High / Medium / Low
    published: str              # ISO-8601 date string
    modified: str
    cwe_ids: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    mitre_attack_ids: list[str] = field(default_factory=list)
    known_exploited: bool = False      # CISA KEV flag
    affected_packages: list[str] = field(default_factory=list)
    source: FeedSource = FeedSource.NVD
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatContext:
    """
    Aggregated threat intelligence for a specific dependency/package query.
    Returned by the retriever; consumed by Risk Scorer and Dashboard.
    """
    package: str
    version: str
    cves: list[CVERecord] = field(default_factory=list)
    max_cvss: float = 0.0
    max_epss: float = 0.0
    known_exploited_count: int = 0
    owasp_categories: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_cves(cls, package: str, version: str, cves: list[CVERecord]) -> "ThreatContext":
        if not cves:
            return cls(package=package, version=version)
        max_cvss = max(c.cvss_score for c in cves)
        max_epss = max((c.epss_score for c in cves if c.epss_score >= 0), default=0.0)
        known_count = sum(1 for c in cves if c.known_exploited)
        owasps: list[str] = []
        mitres: list[str] = []
        for c in cves:
            owasps.extend(c.owasp_categories)
            mitres.extend(c.mitre_attack_ids)
        return cls(
            package=package,
            version=version,
            cves=cves,
            max_cvss=max_cvss,
            max_epss=max_epss,
            known_exploited_count=known_count,
            owasp_categories=list(dict.fromkeys(owasps)),
            mitre_ids=list(dict.fromkeys(mitres)),
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class FeedMetadata:
    """
    Tracks when a feed was last fetched and how many records it holds.
    """
    source: FeedSource
    last_fetched: str     # ISO-8601
    record_count: int
    status: str           # "ok" | "error" | "stale"

    def to_dict(self) -> dict:
        return asdict(self)
