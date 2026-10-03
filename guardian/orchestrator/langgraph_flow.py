"""
AI Code Guardian v3 — LangGraph StateGraph Workflow
===================================================
Defines the LangGraph StateGraph workflow engine powering multi-agent transitions.

Routing is conditional, not a fixed chain: after "security" (always run,
since business/threat/policy all reason over the findings it produces),
business/architecture/dependency/threat_simulation/policy are an optional
chain -- each step's incoming edge checks whether it's actually present in
state["execution_plan"]["agent_order"] (set by PlannerAgent) and, if not,
jumps straight to the next node that IS planned. Patch generation is
skipped the same way, plus a live check that findings actually exist (no
point drafting remediation for zero findings).

business/architecture/dependency are logically independent of each other
(each only reads repository/security context, not one another's output)
and are marked as a parallel_groups entry in the execution plan for a
future phase -- they still run sequentially here. Making them real
LangGraph parallel branches needs a merge/reducer strategy for the shared
state fields they'd write concurrently (findings, evidence), which is a
separate, riskier change deliberately deferred rather than rushed in.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from guardian.orchestrator.events import EventBus
from guardian.orchestrator.planner import PlannerAgent
from guardian.orchestrator.state import AgentWorkflowState
from guardian.orchestrator.tools import ToolRegistry

logger = logging.getLogger(__name__)

# Standard node identifier constants
NODE_PLANNER = "planner"
NODE_REPOSITORY = "repository"
NODE_BUSINESS = "business"
NODE_SECURITY = "security"
NODE_ARCHITECTURE = "architecture"
NODE_DEPENDENCY = "dependency"
NODE_THREAT_SIMULATION = "threat_simulation"
NODE_POLICY = "policy"
NODE_RISK_FUSION = "risk_fusion"
NODE_PATCH = "patch"
NODE_VALIDATION = "validation"

PARALLEL_NODES = [NODE_BUSINESS, NODE_ARCHITECTURE, NODE_DEPENDENCY]
POST_PARALLEL_CHAIN = [NODE_THREAT_SIMULATION, NODE_POLICY]
OPTIONAL_CHAIN = PARALLEL_NODES + POST_PARALLEL_CHAIN


def _first_post_parallel_planned_node(state: "AgentWorkflowState") -> str:
    """Finds the first node after the parallel block (threat_simulation, policy)
    that is in the plan; falls through to risk_fusion if neither is planned."""
    order = (state.get("execution_plan") or {}).get("agent_order", [])
    for name in POST_PARALLEL_CHAIN:
        if name in order:
            return name
    return NODE_RISK_FUSION


def _route_after_security(state: "AgentWorkflowState") -> Any:
    """Fans out concurrently to all requested parallel nodes (business, architecture,
    dependency) if present in agent_order. If none are planned, jumps straight to
    the first post-parallel planned node."""
    order = (state.get("execution_plan") or {}).get("agent_order", [])
    planned_parallel = [name for name in PARALLEL_NODES if name in order]
    if planned_parallel:
        return planned_parallel
    return _first_post_parallel_planned_node(state)


def _route_after_business(state: "AgentWorkflowState") -> str:
    """Converges after business branch to the first planned post-parallel node."""
    return _first_post_parallel_planned_node(state)


def _route_after_architecture(state: "AgentWorkflowState") -> str:
    """Converges after architecture branch to the first planned post-parallel node."""
    return _first_post_parallel_planned_node(state)


def _route_after_dependency(state: "AgentWorkflowState") -> str:
    """Converges after dependency branch to the first planned post-parallel node."""
    return _first_post_parallel_planned_node(state)


def _route_after_threat_simulation(state: "AgentWorkflowState") -> str:
    """Routes from threat_simulation to policy if planned, else risk_fusion."""
    order = (state.get("execution_plan") or {}).get("agent_order", [])
    if NODE_POLICY in order:
        return NODE_POLICY
    return NODE_RISK_FUSION



def _route_after_risk_fusion(state: "AgentWorkflowState") -> str:
    """Patch generation is skipped -- not run as a no-op -- when it isn't
    in the plan (e.g. scan_mode="security_only") or when there are
    genuinely no findings to remediate."""
    order = (state.get("execution_plan") or {}).get("agent_order", [])
    if NODE_PATCH in order and state.get("findings"):
        return NODE_PATCH
    return NODE_VALIDATION


_OPTIONAL_ROUTE_TARGETS = {name: name for name in OPTIONAL_CHAIN}
_OPTIONAL_ROUTE_TARGETS[NODE_RISK_FUSION] = NODE_RISK_FUSION


def create_placeholder_node(agent_name: str) -> Callable[[AgentWorkflowState], AgentWorkflowState]:
    """Factory creating lightweight placeholder nodes for future specialist agents."""
    def placeholder_node(state: AgentWorkflowState) -> AgentWorkflowState:
        new_state = dict(state)
        new_state["current_task"] = f"Placeholder for {agent_name} agent"
        return new_state
    return placeholder_node


def build_workflow_graph(
    planner_agent: Optional[PlannerAgent] = None,
    tool_registry: Optional[ToolRegistry] = None,
    event_bus: Optional[EventBus] = None,
    agent_registry: Optional[Any] = None,
    checkpointer: Optional[Any] = None
) -> Any:
    """
    Constructs and compiles the LangGraph StateGraph.
    Phase 4 layout:
      START -> Planner -> Repository -> Business -> Security -> Architecture -> Dependency -> END
    """
    planner = planner_agent or PlannerAgent(tool_registry=tool_registry, event_bus=event_bus, agent_registry=agent_registry)

    # Helper function to get agent runner node
    def get_agent_node(name: str):
        if agent_registry and hasattr(agent_registry, "get"):
            agent_instance = agent_registry.get(name)
            if agent_instance:
                if hasattr(agent_instance, "run"):
                    return lambda s: agent_instance.run(s)
                elif callable(agent_instance):
                    inst = agent_instance(tool_registry=tool_registry, event_bus=event_bus)
                    return lambda s: inst.run(s)
        return create_placeholder_node(name)

    def planner_node(state: AgentWorkflowState) -> AgentWorkflowState:
        return planner.run(state)

    def trim_messages_node(state: AgentWorkflowState) -> AgentWorkflowState:
        try:
            from langchain_core.messages import RemoveMessage
            messages = state.get("messages", [])
            if len(messages) > 10:
                # Remove oldest messages exceeding the limit of 10
                to_remove = messages[:-10]
                return {"messages": [RemoveMessage(id=m.id) for m in to_remove if hasattr(m, "id")]}
        except ImportError:
            pass
        return {}

    repo_node = get_agent_node(NODE_REPOSITORY)
    biz_node = get_agent_node(NODE_BUSINESS)
    sec_node = get_agent_node(NODE_SECURITY)
    arch_node = get_agent_node(NODE_ARCHITECTURE)
    dep_node = get_agent_node(NODE_DEPENDENCY)
    threat_node = get_agent_node(NODE_THREAT_SIMULATION)
    pol_node = get_agent_node(NODE_POLICY)
    risk_node = get_agent_node(NODE_RISK_FUSION)
    patch_node = get_agent_node(NODE_PATCH)
    val_node = get_agent_node(NODE_VALIDATION)

    try:
        from langgraph.graph import END, START, StateGraph
        from langgraph.prebuilt import ToolNode, tools_condition
        
        try:
            from guardian.agents.chat.agent import InteractiveChatAgent
            chat_agent = InteractiveChatAgent(tool_registry=tool_registry, event_bus=event_bus)
            tool_node = ToolNode(chat_agent.tools)
        except Exception as e:
            logger.info("InteractiveChatAgent not loaded: %s", e)
            chat_agent = None
            tool_node = None
            
        def route_workflow_start(state: AgentWorkflowState) -> str:
            return "chat_agent" if state.get("scan_mode") == "chat" else NODE_PLANNER

        builder = StateGraph(AgentWorkflowState)

        # 1. Register Nodes
        builder.add_node("trim_messages", trim_messages_node)
        if chat_agent:
            builder.add_node("chat_agent", chat_agent.run)
            builder.add_node("tools", tool_node)
            
        builder.add_node(NODE_PLANNER, planner_node)
        builder.add_node(NODE_REPOSITORY, repo_node)
        builder.add_node(NODE_BUSINESS, biz_node)
        builder.add_node(NODE_SECURITY, sec_node)
        builder.add_node(NODE_ARCHITECTURE, arch_node)
        builder.add_node(NODE_DEPENDENCY, dep_node)
        builder.add_node(NODE_THREAT_SIMULATION, threat_node)
        builder.add_node(NODE_POLICY, pol_node)
        builder.add_node(NODE_RISK_FUSION, risk_node)
        builder.add_node(NODE_PATCH, patch_node)
        builder.add_node(NODE_VALIDATION, val_node)

        # 2. Register Edges
        builder.add_edge(START, "trim_messages")
        
        if chat_agent:
            builder.add_conditional_edges("trim_messages", route_workflow_start, {NODE_PLANNER: NODE_PLANNER, "chat_agent": "chat_agent"})
            builder.add_conditional_edges("chat_agent", tools_condition, {"tools": "tools", "__end__": END})
            builder.add_edge("tools", "chat_agent")
        else:
            builder.add_edge("trim_messages", NODE_PLANNER)
            
        builder.add_edge(NODE_PLANNER, NODE_REPOSITORY)
        # repository -> security always runs: it's the core deterministic
        # pass everything else (business/threat/policy/risk) reasons over.
        builder.add_edge(NODE_REPOSITORY, NODE_SECURITY)
        # security -> {business, architecture, dependency, threat_simulation,
        # policy, risk_fusion}: the optional chain, gated live against
        # execution_plan.agent_order rather than a fixed next-step.
        builder.add_conditional_edges(NODE_SECURITY, _route_after_security, dict(_OPTIONAL_ROUTE_TARGETS))
        builder.add_conditional_edges(NODE_BUSINESS, _route_after_business, dict(_OPTIONAL_ROUTE_TARGETS))
        builder.add_conditional_edges(NODE_ARCHITECTURE, _route_after_architecture, dict(_OPTIONAL_ROUTE_TARGETS))
        builder.add_conditional_edges(NODE_DEPENDENCY, _route_after_dependency, dict(_OPTIONAL_ROUTE_TARGETS))
        builder.add_conditional_edges(NODE_THREAT_SIMULATION, _route_after_threat_simulation, dict(_OPTIONAL_ROUTE_TARGETS))
        builder.add_edge(NODE_POLICY, NODE_RISK_FUSION)
        # risk_fusion -> {patch, validation}: patch is skipped (not run as
        # a no-op) when it isn't planned or there are no findings.
        builder.add_conditional_edges(
            NODE_RISK_FUSION, _route_after_risk_fusion,
            {NODE_PATCH: NODE_PATCH, NODE_VALIDATION: NODE_VALIDATION},
        )
        builder.add_edge(NODE_PATCH, NODE_VALIDATION)
        builder.add_edge(NODE_VALIDATION, END)

        return builder.compile(checkpointer=checkpointer)

    except Exception as exc:
        logger.warning(f"Using fallback StateGraph runner due to: {exc}")

        # Fallback deterministic graph runner mimicking LangGraph interface.
        # Mirrors the same conditional routing as the StateGraph build above:
        # security always runs right after repository (business/threat/policy
        # all reason over its findings), then the optional chain is walked in
        # order but each step is skipped -- not executed as a no-op -- unless
        # it's present in state["execution_plan"]["agent_order"], and patch
        # generation only runs when it's planned AND there are findings to
        # remediate. Previously this ran every node unconditionally in a
        # fixed business-before-security order, ignoring the execution plan
        # entirely whenever the real langgraph StateGraph wasn't available.
        class FallbackCompiledGraph:
            def __init__(self, node_map: Dict[str, Callable[[AgentWorkflowState], AgentWorkflowState]]) -> None:
                self.node_map = node_map

            def invoke(self, state: AgentWorkflowState, config: Optional[Dict[str, Any]] = None, **kwargs: Any) -> AgentWorkflowState:
                current_state = self.node_map[NODE_PLANNER](state)
                current_state = self.node_map[NODE_REPOSITORY](current_state)
                current_state = self.node_map[NODE_SECURITY](current_state)

                order = (current_state.get("execution_plan") or {}).get("agent_order", [])
                planned_parallel = [name for name in PARALLEL_NODES if name in order]

                if len(planned_parallel) > 1:
                    import concurrent.futures
                    from guardian.orchestrator.state import merge_dict, merge_list

                    def _run_branch(name: str) -> Dict[str, Any]:
                        return self.node_map[name](dict(current_state))

                    with concurrent.futures.ThreadPoolExecutor(max_workers=len(planned_parallel)) as executor:
                        futures = [executor.submit(_run_branch, name) for name in planned_parallel]
                        results = [f.result() for f in futures]

                    for res in results:
                        for k, v in res.items():
                            if k not in current_state or current_state[k] is None:
                                current_state[k] = v
                            elif isinstance(v, list):
                                current_state[k] = merge_list(current_state.get(k, []), v)
                            elif isinstance(v, dict):
                                current_state[k] = merge_dict(current_state.get(k, {}), v)
                            else:
                                current_state[k] = v
                elif len(planned_parallel) == 1:
                    current_state = self.node_map[planned_parallel[0]](current_state)

                for name in POST_PARALLEL_CHAIN:
                    if name in order:
                        current_state = self.node_map[name](current_state)

                current_state = self.node_map[NODE_RISK_FUSION](current_state)

                if NODE_PATCH in order and current_state.get("findings"):
                    current_state = self.node_map[NODE_PATCH](current_state)

                current_state = self.node_map[NODE_VALIDATION](current_state)
                return current_state

            async def ainvoke(self, state: AgentWorkflowState, config: Optional[Dict[str, Any]] = None, **kwargs: Any) -> AgentWorkflowState:
                return self.invoke(state, config=config, **kwargs)

        return FallbackCompiledGraph({
            NODE_PLANNER: planner_node,
            NODE_REPOSITORY: repo_node,
            NODE_BUSINESS: biz_node,
            NODE_SECURITY: sec_node,
            NODE_ARCHITECTURE: arch_node,
            NODE_DEPENDENCY: dep_node,
            NODE_THREAT_SIMULATION: threat_node,
            NODE_POLICY: pol_node,
            NODE_RISK_FUSION: risk_node,
            NODE_PATCH: patch_node,
            NODE_VALIDATION: val_node,
        })
