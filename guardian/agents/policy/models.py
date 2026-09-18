"""
AI Code Guardian v3 — Policy Agent Models & Exports
===================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class PolicyEvaluationSummary:
    total_violations: int = 0
    failed_policies: List[str] = field(default_factory=list)
