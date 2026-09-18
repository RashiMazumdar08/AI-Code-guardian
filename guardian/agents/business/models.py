"""
AI Code Guardian v3 — Business Agent Models & Package Exports
=============================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class BusinessDomainClassification:
    domain: str = "general"
    criticality: str = "NORMAL"
    compliance: List[str] = field(default_factory=list)
