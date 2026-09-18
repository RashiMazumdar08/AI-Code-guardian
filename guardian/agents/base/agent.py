"""
AI Code Guardian v3 — Base Agent Class
======================================
Abstract base class for all specialist agents. Provides uniform state management,
telemetry, tool access, event distribution, and trace logging.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from guardian.orchestrator.events import EventBus, TaskCompleted, TaskScheduled
from guardian.orchestrator.state import AgentTrace, AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class inherited by all specialist AI agents."""

    name: str = "base_agent"
    description: str = "Base agent interface"

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        event_bus: Optional[EventBus] = None
    ) -> None:
        self.tools = tool_registry or ToolRegistry()
        self.event_bus = event_bus
        self.logger = logging.getLogger(f"guardian.agents.{self.name}")

    def run(self, state: AgentWorkflowState) -> AgentWorkflowState:
        """
        Public execution wrapper handling telemetry, events, trace generation,
        and state updates around the agent's core implementation.
        """
        scan_id = state.get("scan_id", "")
        self.logger.info(f"Starting execution of agent '{self.name}' for scan '{scan_id}'")

        if self.event_bus:
            self.event_bus.publish(TaskScheduled(agent_name=self.name, task_name=self.description))

        t0 = time.perf_counter()

        # Mark active agent and update state
        working_state = dict(state)
        working_state["active_agent"] = self.name
        working_state["current_task"] = self.description

        # Remove from pending if present
        pending = list(working_state.get("pending_agents", []))
        if self.name in pending:
            pending.remove(self.name)
        working_state["pending_agents"] = pending

        errors: List[str] = []
        result_payload: Dict[str, Any] = {}

        try:
            working_state = self._process(working_state)
            result_payload = {"status": "success"}
        except Exception as e:
            self.logger.exception(f"Error executing agent '{self.name}': {e}")
            errors.append(str(e))
            result_payload = {"status": "error", "error": str(e)}

        elapsed = time.perf_counter() - t0

        # Mark completed
        completed = list(working_state.get("completed_agents", []))
        if self.name not in completed:
            completed.append(self.name)
        working_state["completed_agents"] = completed

        # Append Agent Trace
        trace_record: AgentTrace = {
            "agent_name": self.name,
            "execution_time": elapsed,
            "current_task": self.description,
            "tools_used": getattr(self, "_used_tools", []),
            "evidence_ids": getattr(self, "_generated_evidence_ids", []),
            "confidence": getattr(self, "_confidence", 1.0),
            "result": result_payload,
            "errors": errors,
        }

        traces = list(working_state.get("agent_trace", []))
        traces.append(trace_record)
        working_state["agent_trace"] = traces

        # Update Metrics
        metrics = dict(working_state.get("execution_metrics", {}))
        runtimes = dict(metrics.get("agent_runtime", {}))
        runtimes[self.name] = elapsed
        metrics["agent_runtime"] = runtimes
        working_state["execution_metrics"] = metrics

        if self.event_bus:
            self.event_bus.publish(
                TaskCompleted(
                    agent_name=self.name,
                    task_name=self.description,
                    duration=elapsed,
                    status=result_payload.get("status", "success"),
                    error=result_payload.get("error", ""),
                )
            )

        self.logger.info(f"Finished agent '{self.name}' in {elapsed:.3f}s")
        return working_state

    @abstractmethod
    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        """Internal core logic implemented by specialist subclasses."""
        pass
