"""
AI Code Guardian v3 — Dashboard Risk Charts
===========================================
Generates data chart definitions and HTML/SVG visual representations for risk scores.
"""
from __future__ import annotations

from typing import Any, Dict


class RiskChartGenerator:
    """Generates visual chart models for risk scores and severity distributions."""

    def generate_risk_breakdown(self, risk_scores: Dict[str, Any]) -> Dict[str, Any]:
        """Generates risk breakdown dataset across technical, business, threat, and policy dimensions."""
        return {
            "chart_type": "radar",
            "categories": ["Technical Risk", "Business Risk", "Threat Risk", "Policy Risk"],
            "values": [
                risk_scores.get("technical_risk_score", 0.0),
                risk_scores.get("business_risk_score", 0.0),
                risk_scores.get("threat_risk_score", 0.0),
                risk_scores.get("policy_risk_score", 0.0),
            ],
            "composite_score": risk_scores.get("composite_risk_score", 0.0),
            "risk_level": risk_scores.get("risk_level", "UNKNOWN"),
        }

    def generate_severity_distribution(self, findings: list) -> Dict[str, int]:
        """Calculates finding counts grouped by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["INFO"] += 1
        return counts
