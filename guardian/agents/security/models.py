"""
AI Code Guardian v3 — Security Agent Models & Package Exports
============================================================
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SecurityScanSummary:
    total_findings: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
