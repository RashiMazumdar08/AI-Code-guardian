"""
AI Code Guardian v3 — Validation Agent Models & Exports
======================================================
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class ValidationSummary:
    total_validated: int = 0
    passed_count: int = 0
    rejected_count: int = 0
