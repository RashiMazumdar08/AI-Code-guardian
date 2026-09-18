"""
AI Code Guardian v3 — Threat Simulation Agent Models & Exports
==============================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ThreatModelSummary:
    max_exploitability: float = 0.0
    total_attack_paths: int = 0
