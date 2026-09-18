"""
AI Code Guardian v3 — Dashboard State View Model
================================================
Parses AgentWorkflowState into clean read-only view properties for UI rendering.
Never mutates backend workflow state or executes agents.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from guardian.orchestrator.state import AgentWorkflowState


class DashboardStateView:
    """Read-only view model consuming AgentWorkflowState for UI presentation."""

    def __init__(self, state: AgentWorkflowState) -> None:
        self._state = state

    @property
    def scan_id(self) -> str:
        return self._state.get("scan_id", "UNKNOWN")

    @property
    def repository_profile(self) -> Dict[str, Any]:
        return self._state.get("repository_profile", {})

    @property
    def business_context(self) -> Dict[str, Any]:
        return self._state.get("business_context", {})

    @property
    def repository_context(self) -> Dict[str, Any]:
        return self._state.get("repository_context", {})

    @property
    def security_context(self) -> Dict[str, Any]:
        return self._state.get("security_context", {})

    @property
    def architecture_context(self) -> Dict[str, Any]:
        return self._state.get("architecture_context", {})

    @property
    def dependency_context(self) -> Dict[str, Any]:
        return self._state.get("dependency_context", {})

    @property
    def threat_context(self) -> Dict[str, Any]:
        return self._state.get("threat_context", {})

    @property
    def policy_results(self) -> Dict[str, Any]:
        return self._state.get("policy_results", {})

    @property
    def risk_scores(self) -> Dict[str, Any]:
        return self._state.get("risk_scores", {})

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self._state.get("findings", [])

    @property
    def evidence(self) -> List[Dict[str, Any]]:
        return self._state.get("evidence", [])

    @property
    def patches(self) -> List[Dict[str, Any]]:
        return self._state.get("patches", [])

    @property
    def validation_results(self) -> List[Dict[str, Any]]:
        return self._state.get("validation_results", [])

    @property
    def git_diff(self) -> str:
        return self._state.get("git_diff", "")

    @property
    def developer_explanation(self) -> str:
        return self._state.get("developer_explanation", "")

    @property
    def agent_trace(self) -> List[Dict[str, Any]]:
        traces = self._state.get("agent_trace", [])
        return [t if isinstance(t, dict) else dict(t) for t in traces]

    @property
    def execution_metrics(self) -> Dict[str, Any]:
        return self._state.get("execution_metrics", {})
