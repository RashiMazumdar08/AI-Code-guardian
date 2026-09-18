"""
AI Code Guardian v3 — Planner Agent
===================================
Orchestrates agent execution strategy based on repository profile, business intent,
policies, and graph context. Does NOT scan vulnerabilities directly.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from guardian.orchestrator.events import EventBus, PlannerCompleted
from guardian.orchestrator.state import AgentTrace, AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry


# The full specialist chain in dependency order. "security" runs before the
# optional analysis agents because business/threat/policy all reason over
# findings the security engine produces -- planning them before security
# would leave them with nothing to consume.
FULL_AGENT_ORDER = [
    "repository", "security", "business", "architecture", "dependency",
    "threat_simulation", "policy", "risk_fusion", "patch", "validation",
]
#: Always run regardless of scan_mode -- the minimum chain that still
#: produces a real risk assessment.
CORE_AGENTS = {"repository", "security", "risk_fusion", "validation"}
#: Excluded when scan_mode == "security_only": business/compliance/
#: remediation branches that a pure security pass doesn't need.
SECURITY_ONLY_EXCLUDE = {"business", "architecture", "threat_simulation", "policy", "patch"}


@dataclass
class ExecutionPlan:
    """Dataclass holding the strategic plan for downstream agent execution."""
    agent_order: List[str] = field(default_factory=list)
    parallel_groups: List[List[str]] = field(default_factory=list)
    required_agents: List[str] = field(default_factory=list)
    optional_agents: List[str] = field(default_factory=list)
    priority: str = "NORMAL"
    reason: str = ""
    expected_inputs: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    confidence: float = 1.0


class PlannerAgent:
    """
    Planner Agent reads structural and domain metadata to build an ExecutionPlan.
    Communicates exclusively through AgentWorkflowState and ToolRegistry.
    """

    name: str = "planner"

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        event_bus: Optional[EventBus] = None,
        agent_registry: Optional[Any] = None
    ) -> None:
        self.tools = tool_registry or ToolRegistry()
        self.event_bus = event_bus
        self.agent_registry = agent_registry

    def run(self, state: AgentWorkflowState) -> AgentWorkflowState:
        """Executes planning logic and returns updated workflow state."""
        t0 = time.perf_counter()

        repo_profile = state.get("repository_profile", {})
        business_context = state.get("business_context", {})
        policy_context = state.get("policy_context", {})

        # Query tools for contextual metadata if needed
        policy_res = self.tools.execute("policy_tool", frameworks=policy_context.get("frameworks", []))
        intent_res = self.tools.execute("business_intent_tool", business_context=business_context)

        # Build the actual execution strategy -- this is a real branch, not
        # a decorative label: build_workflow_graph()'s conditional edges
        # read agent_order back out of state.execution_plan at runtime to
        # decide which nodes to skip, so a wrong decision here changes what
        # the graph actually executes.
        scan_mode = state.get("scan_mode", "full_scan")

        if scan_mode == "security_only":
            excluded = SECURITY_ONLY_EXCLUDE
            reason = (
                f"scan_mode='security_only': business/architecture/threat-simulation/"
                f"policy/patch branches skipped -- running only the core security + "
                f"dependency + risk chain. Repository frameworks: {repo_profile.get('frameworks', [])}."
            )
        else:
            excluded = set()
            reason = (
                f"scan_mode='{scan_mode}': full analysis chain. "
                f"Repository frameworks: {repo_profile.get('frameworks', [])}. "
                f"Business context domain: {business_context.get('domain', 'general')}. "
                f"Configured policies: {policy_res.get('active_policies', [])}."
            )

        default_order = [a for a in FULL_AGENT_ORDER if a not in excluded]

        if self.agent_registry and hasattr(self.agent_registry, "list_agents"):
            registered = set(self.agent_registry.list_agents())
            agent_order = [a for a in default_order if a in registered]
            missing = [a for a in default_order if a not in registered]
            if missing:
                reason += f" (not registered, so also skipped: {missing})"
        else:
            agent_order = default_order

        required_agents = [a for a in agent_order if a in CORE_AGENTS]
        optional_agents = [a for a in agent_order if a not in CORE_AGENTS]

        # Everything between "security" and "risk_fusion" only reads
        # repository/security context, not each other's output, so it's
        # safe to run them concurrently once the graph supports fan-out --
        # recorded here as the intended grouping even though the current
        # graph still executes this chain sequentially (see
        # langgraph_flow.py's module docstring for why that's deferred).
        parallel_groups = [[a for a in ("business", "architecture", "dependency") if a in agent_order]]
        parallel_groups = [g for g in parallel_groups if len(g) > 1]

        priority = "HIGH" if business_context.get("criticality") == "CRITICAL" else "NORMAL"

        plan = ExecutionPlan(
            agent_order=agent_order,
            parallel_groups=parallel_groups,
            required_agents=required_agents,
            optional_agents=optional_agents,
            priority=priority,
            reason=reason,
            expected_inputs=["repository_profile", "repository_graph", "business_context", "policy_context"],
            expected_outputs=["findings", "evidence", "risk_scores", "patches", "reports"],
            confidence=0.95,
        )

        elapsed = time.perf_counter() - t0

        # Update Workflow State
        new_state = dict(state)
        new_state["execution_plan"] = asdict(plan)
        new_state["active_agent"] = "planner"
        new_state["pending_agents"] = list(agent_order)

        completed = list(new_state.get("completed_agents", []))
        if "planner" not in completed:
            completed.append("planner")
        new_state["completed_agents"] = completed

        # Record Agent Trace
        trace_record: AgentTrace = {
            "agent_name": self.name,
            "execution_time": elapsed,
            "current_task": "Generate Execution Strategy",
            "tools_used": ["policy_tool", "business_intent_tool"],
            "evidence_ids": [],
            "confidence": plan.confidence,
            "result": {"agent_order": plan.agent_order, "priority": plan.priority},
            "errors": [],
        }

        traces = list(new_state.get("agent_trace", []))
        traces.append(trace_record)
        new_state["agent_trace"] = traces

        # Update Metrics
        metrics = dict(new_state.get("execution_metrics", {}))
        agent_runtimes = dict(metrics.get("agent_runtime", {}))
        agent_runtimes["planner"] = elapsed
        metrics["agent_runtime"] = agent_runtimes
        new_state["execution_metrics"] = metrics

        # Emit Event
        if self.event_bus:
            self.event_bus.publish(
                PlannerCompleted(
                    scan_id=new_state.get("scan_id", ""),
                    agent_order=plan.agent_order
                )
            )

        return new_state
