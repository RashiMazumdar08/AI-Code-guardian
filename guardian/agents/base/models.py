"""
AI Code Guardian v3 — Base Agent Models
=======================================
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AgentResult:
    """Standardized return structure from internal agent process execution."""
    status: str = "success"
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
