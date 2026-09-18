"""
AI Code Guardian v3 — Risk Fusion Agent Models & Exports
========================================================
"""
from dataclasses import dataclass


@dataclass
class RiskCompositeSummary:
    composite_score: float = 0.0
    risk_level: str = "LOW"
    confidence: float = 1.0
