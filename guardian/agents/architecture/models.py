"""
AI Code Guardian v3 — Architecture Agent Models & Package Exports
==================================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ArchitectureTopology:
    service_count: int = 1
    trust_boundaries: List[str] = field(default_factory=list)
