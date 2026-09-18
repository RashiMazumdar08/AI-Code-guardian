"""
AI Code Guardian v3 — Patch Proposal Model
=========================================
Data structure representing a grounded, validated remediation patch suggestion.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PatchProposal:
    """Represents a grounded patch proposal generated for a security finding."""
    patch_id: str
    finding_id: str
    affected_file: str
    affected_lines: str = "1"
    original_snippet: str = ""
    suggested_replacement: str = ""
    explanation: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.90
    policy_references: List[str] = field(default_factory=list)
    business_impact: str = "LOW"
    threat_impact: str = "LOW"
    validation_status: str = "PENDING"
    git_diff: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
