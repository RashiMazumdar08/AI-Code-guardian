"""
AI Code Guardian v3 — Dependency Agent Models & Package Exports
================================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class DependencyInventory:
    total_packages: int = 0
    manifests: List[str] = field(default_factory=list)
