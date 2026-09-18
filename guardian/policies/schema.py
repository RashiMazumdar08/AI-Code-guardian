"""
AI Code Guardian v3 — Policy Schema & Policy Rule Definitions
=============================================================
Data models for organizational policy packs, rule enforcement, and compliance bounds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyRule:
    rule_id: str
    name: str
    severity: str = "MEDIUM"
    category: str = "general"
    description: str = ""
    target: str = ""
    condition: Dict[str, Any] = field(default_factory=dict)
    action: str = "FLAG"


@dataclass
class PolicyPack:
    name: str
    version: str = "1.0.0"
    description: str = ""
    rules: List[PolicyRule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
