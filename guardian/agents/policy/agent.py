"""
AI Code Guardian v3 — Policy Reasoning Agent
============================================
Specialist agent evaluating security findings against compliance policy packs
(OWASP, NIST, PCI-DSS, organization policies) using PolicyPackManager.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import PolicyResults
from guardian.orchestrator.state import AgentWorkflowState
from guardian.policies.manager import PolicyPackManager


class PolicyAgent(BaseAgent):
    """Specialist agent assessing policy compliance, violations, and rule overrides."""

    name: str = "policy"
    description: str = "Evaluates findings against active organization and compliance policy packs."

    def __init__(
        self,
        tool_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        policy_manager: Optional[PolicyPackManager] = None
    ) -> None:
        super().__init__(tool_registry=tool_registry, event_bus=event_bus)
        self.policy_manager = policy_manager or PolicyPackManager()

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["policy_tool"]

        findings = state.get("findings", [])
        policy_ctx = state.get("policy_context", {})
        active_packs = policy_ctx.get("frameworks") or ["OWASP_TOP_10", "NIST_800_53"]

        eval_results = self.policy_manager.evaluate_findings(findings, active_pack_names=active_packs)

        policy_res_obj: PolicyResults = {
            "total_violations": eval_results["total_violations"],
            "violations": eval_results["violations"],
            "passed_policies": eval_results["passed_policies"],
            "failed_policies": eval_results["failed_policies"],
            "overrides": eval_results["overrides"],
        }

        new_state = dict(state)
        new_state["policy_results"] = dict(policy_res_obj)

        # Merge policy info into policy_context
        merged_policy_context = dict(policy_ctx)
        merged_policy_context["total_violations"] = eval_results["total_violations"]
        merged_policy_context["failed_policies"] = eval_results["failed_policies"]
        new_state["policy_context"] = merged_policy_context

        return new_state
