"""
AI Code Guardian v3 — Agent Studio Page
=======================================
Detailed inspection interface for all 11 specialist agents in the LangGraph StateGraph pipeline.
"""
from __future__ import annotations

from typing import Any, Dict, List
from guardian.dashboard.models.dashboard_state import DashboardStateView


class AgentStudioPage:
    """Renders Agent Studio view displaying deep telemetry for all 11 agents."""

    AGENTS_LIST = [
        "planner", "repository", "business", "security", "architecture",
        "dependency", "threat_simulation", "policy", "risk_fusion", "patch", "validation"
    ]

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        traces = state_view.agent_trace
        metrics = state_view.execution_metrics.get("agent_runtime", {})

        agent_cards: List[Dict[str, Any]] = []
        for name in self.AGENTS_LIST:
            trace_obj = next((t for t in traces if t.get("agent_name") == name), None)
            runtime = metrics.get(name, trace_obj.get("execution_time", 0.0) if trace_obj else 0.0)

            card = {
                "agent_name": name,
                "status": "COMPLETED" if trace_obj else ("SKIPPED" if name not in state_view._state.get("completed_agents", []) else "PENDING"),
                "execution_time": runtime,
                "current_task": trace_obj.get("current_task", f"Specialist reasoning for {name}") if trace_obj else f"{name} task",
                "tools_used": trace_obj.get("tools_used", []) if trace_obj else [],
                "evidence_ids": trace_obj.get("evidence_ids", []) if trace_obj else [],
                "confidence": trace_obj.get("confidence", 1.0) if trace_obj else 1.0,
                "result": trace_obj.get("result", {}) if trace_obj else {},
                "errors": trace_obj.get("errors", []) if trace_obj else [],
            }
            agent_cards.append(card)

        return {
            "page_title": "Agent Studio (11 Specialist Agents)",
            "total_agents": len(self.AGENTS_LIST),
            "agents": agent_cards,
        }
