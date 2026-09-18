"""
AI Code Guardian v3 — Operational Metrics Dashboard Page
========================================================
Visualizes performance metrics, agent/tool execution runtimes, query durations, and finding distributions.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.charts.metrics_charts import MetricsChartGenerator
from guardian.dashboard.models.dashboard_state import DashboardStateView


class MetricsDashboardPage:
    """Renders Metrics Dashboard view."""

    def __init__(self, metrics_generator: Optional[MetricsChartGenerator] = None) -> None:
        self.generator = metrics_generator or MetricsChartGenerator()

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        metrics = state_view.execution_metrics
        summary = self.generator.generate_performance_summary(metrics)

        return {
            "page_title": "Operational Metrics & Performance Observability",
            "total_execution_time": metrics.get("total_execution_time", 0.0),
            "number_of_findings": metrics.get("number_of_findings", len(state_view.findings)),
            "number_of_evidence_objects": metrics.get("number_of_evidence_objects", len(state_view.evidence)),
            "performance_summary": summary,
            "agent_runtime_breakdown": metrics.get("agent_runtime", {}),
        }
