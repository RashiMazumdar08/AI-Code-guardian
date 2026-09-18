"""
AI Code Guardian v3 — Workflow Timeline Page
============================================
Visualizes LangGraph StateGraph agent execution timeline, order, and status.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.charts.timeline_charts import TimelineChartGenerator
from guardian.dashboard.models.dashboard_state import DashboardStateView


class WorkflowTimelinePage:
    """Renders LangGraph Workflow Timeline view."""

    def __init__(self, timeline_generator: Optional[TimelineChartGenerator] = None) -> None:
        self.generator = timeline_generator or TimelineChartGenerator()

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        trace = state_view.agent_trace
        metrics = state_view.execution_metrics
        items = self.generator.generate_timeline(trace, metrics)

        return {
            "page_title": "Workflow Execution Timeline",
            "total_agents": len(items),
            "timeline": items,
            "total_execution_time": metrics.get("total_execution_time", 0.0),
        }
