"""
AI Code Guardian v3 — Repository Agent Models & Package Exports
================================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class RepositorySummary:
    primary_language: str = ""
    frameworks: List[str] = field(default_factory=list)
    total_entry_points: int = 0
