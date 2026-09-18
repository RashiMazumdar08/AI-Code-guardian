"""
AI Code Guardian - Core Data Models
Universal AST node shapes + Finding/ScanResult contracts shared by every
detector and consumed downstream by the Risk Scorer and Dashboard.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TaintLabel(str, Enum):
    SOURCE = "source"          # user-controlled input (HTTP param, env var, file read)
    SANITIZED = "sanitized"    # passed through a recognised sanitiser
    SINK = "sink"               # dangerous operation (SQL exec, OS exec, eval, etc.)


@dataclass
class SourceLocation:
    file_path: str
    line: int
    column: int = 0


@dataclass
class Finding:
    """
    A single security finding. `to_dict()` output is intentionally flat
    and stable so it can feed directly into the Day-7 Risk Scorer and the
    Streamlit dashboard without transformation.

    Fields after `tainted` were added by the UST/evidence refactor. They
    are all optional with inert defaults, so every pre-existing detector
    and reporter keeps working untouched; detectors that DO have the
    information (language, enclosing function, supporting evidence IDs,
    provenance) populate them so reports can explain *why* a finding
    exists and whether a human or a model asserted it.
    """
    category: str
    severity: str
    rule_id: Optional[str]
    file: str
    line: int
    snippet: str
    recommendation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: float = 0.9          # detector self-reported confidence (0-1)
    tainted: bool = False            # True if confirmed via data-flow tracing

    # -- provenance / explainability (UST + evidence refactor) ----------
    language: str = ""
    function: str = ""               # enclosing function/method when known
    end_line: int = 0
    column: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    source: str = "DETERMINISTIC"    # DETERMINISTIC | AI_VALIDATED | AI_SUGGESTED
    reason: str = ""                 # why this was raised, in one sentence
    engine: str = ""                 # producing engine name

    # -- reachability & AI reasoning enhancements -----------------------
    is_exploitable: bool = False     # True if untrusted input reaches vulnerable sink
    exploitability_score: float = 0.0 # 0.0 - 1.0 likelihood score
    exploit_scenario: str = ""      # Short description of attack vector/payload
    business_impact: str = ""       # Financial/compliance risk summary
    remediation_patch: str = ""     # AST-safe diff or recommended fix code

    finding_id: str = field(default="", init=False)

    def __post_init__(self):
        # Stable SHA-256 id for dedup across incremental scans (Day 4 design).
        basis = f"{self.file}:{self.line}:{self.category}:{self.rule_id}"
        self.finding_id = hashlib.sha256(basis.encode()).hexdigest()[:16]

    @property
    def is_ai(self) -> bool:
        return self.source.startswith("AI")

    def to_dict(self) -> dict:
        return asdict(self) | {"finding_id": self.finding_id}


@dataclass
class ScanResult:
    target: str
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    scan_mode: str = "precision"

    def finish(self):
        self.finished_at = time.time()

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 3)

    @property
    def total_alerts(self) -> int:
        return len(self.findings)

    @property
    def exploitable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_exploitable)

    @property
    def high_priority_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in (Severity.CRITICAL.value, Severity.HIGH.value))

    @property
    def immediate_risk_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.is_exploitable and f.severity in (Severity.CRITICAL.value, Severity.HIGH.value)
        )

    @property
    def counts_by_severity(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def counts_by_category(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "files_scanned": self.files_scanned,
            "duration_seconds": self.duration_seconds,
            "total_findings": len(self.findings),
            "funnel_metrics": {
                "total_alerts": self.total_alerts,
                "exploitable_count": self.exploitable_count,
                "high_priority_count": self.high_priority_count,
                "immediate_risk_count": self.immediate_risk_count,
            },
            "by_severity": self.counts_by_severity,
            "by_category": self.counts_by_category,
            "findings": [f.to_dict() for f in self.findings],
        }
