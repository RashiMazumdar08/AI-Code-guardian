"""
AI Code Guardian v3 — Risk Dashboard Page
=========================================
Visualizes composite risk score, technical/business/threat/policy risk breakdown, and severity distributions.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.charts.risk_charts import RiskChartGenerator
from guardian.dashboard.models.dashboard_state import DashboardStateView


class RiskDashboardPage:
    """Renders Risk Dashboard view."""

    def __init__(self, risk_chart_generator: Optional[RiskChartGenerator] = None) -> None:
        self.generator = risk_chart_generator or RiskChartGenerator()

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        risk_scores = state_view.risk_scores
        findings = state_view.findings

        risk_breakdown = self.generator.generate_risk_breakdown(risk_scores)
        severity_dist = self.generator.generate_severity_distribution(findings)

        return {
            "page_title": "Risk & Compliance Dashboard",
            "composite_risk_score": risk_scores.get("composite_risk_score", 0.0),
            "risk_level": risk_scores.get("risk_level", "LOW"),
            "confidence_score": risk_scores.get("confidence_score", 0.90),
            "risk_breakdown": risk_breakdown,
            "severity_distribution": severity_dist,
            "top_findings": findings[:5],
        }
