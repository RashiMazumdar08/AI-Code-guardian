"""
AI Code Guardian v3 — Dashboard Metrics Charts
==============================================
Generates operational metrics performance summaries and tool runtime charts.
"""
from __future__ import annotations

from typing import Any, Dict


class MetricsChartGenerator:
    """Generates execution metrics chart datasets."""

    def generate_performance_summary(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Summarizes total execution time, findings count, and evidence count."""
        return {
            "total_execution_time": metrics.get("total_execution_time", 0.0),
            "number_of_findings": metrics.get("number_of_findings", 0),
            "number_of_evidence_objects": metrics.get("number_of_evidence_objects", 0),
            "agent_runtime_breakdown": metrics.get("agent_runtime", {}),
        }
