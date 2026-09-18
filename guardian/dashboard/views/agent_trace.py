"""
AI Code Guardian v3 — Agent Trace Explorer Page
===============================================
Deep-dive view into AgentTrace objects: inputs, outputs, evidence IDs, tools, confidence, errors.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView


class AgentTraceExplorerPage:
    """Renders Agent Trace Explorer view."""

    def render(self, state_view: DashboardStateView, selected_agent: Optional[str] = None) -> Dict[str, Any]:
        traces = state_view.agent_trace

        if selected_agent:
            filtered = [t for t in traces if t.get("agent_name") == selected_agent]
        else:
            filtered = traces

        return {
            "page_title": "Agent Trace Explorer",
            "selected_agent": selected_agent,
            "total_traces": len(filtered),
            "traces": filtered,
        }
