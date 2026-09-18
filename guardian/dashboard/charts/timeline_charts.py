"""
AI Code Guardian v3 — Dashboard Timeline Charts
===============================================
Generates execution timeline breakdown charts for the 10 specialist agents.
"""
from __future__ import annotations

from typing import Any, Dict, List


class TimelineChartGenerator:
    """Generates execution timeline datasets for LangGraph StateGraph agent runs."""

    def generate_timeline(self, agent_trace: List[Dict[str, Any]], execution_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generates timeline breakdown dataset with execution order and durations."""
        timeline_items = []
        runtimes = execution_metrics.get("agent_runtime", {})

        for idx, trace in enumerate(agent_trace):
            name = trace.get("agent_name", f"agent-{idx+1}")
            dur = runtimes.get(name, trace.get("execution_time", 0.0))
            timeline_items.append({
                "step": idx + 1,
                "agent_name": name,
                "duration_seconds": round(float(dur), 4),
                "confidence": trace.get("confidence", 0.90),
                "status": "COMPLETED" if not trace.get("errors") else "FAILED",
                "task": trace.get("current_task", ""),
            })

        return timeline_items
