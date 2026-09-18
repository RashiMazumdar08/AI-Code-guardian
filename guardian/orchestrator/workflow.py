"""
AI Code Guardian v3 — Orchestrator Workflow Facade
==================================================
Master workflow facade orchestrating LangGraph execution, shared state,
tool/agent registries, event emission, and metrics collection.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from guardian.orchestrator.events import EventBus, WorkflowCompleted, WorkflowStarted
from guardian.orchestrator.langgraph_flow import build_workflow_graph
from guardian.orchestrator.planner import PlannerAgent
from guardian.orchestrator.registry import AgentRegistry
from guardian.orchestrator.state import AgentWorkflowState, create_initial_state
from guardian.orchestrator.tools import ToolRegistry


class OrchestratorWorkflow:
    """Master orchestration engine running multi-agent workflows."""

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        agent_registry: Optional[AgentRegistry] = None,
        event_bus: Optional[EventBus] = None
    ) -> None:
        self.tools = tool_registry or ToolRegistry()
        self.agent_registry = agent_registry or AgentRegistry()
        self.event_bus = event_bus or EventBus()

        from guardian.agents.architecture import ArchitectureAgent
        from guardian.agents.business import BusinessAgent
        from guardian.agents.dependency import DependencyAgent
        from guardian.agents.patch import PatchGenerationAgent
        from guardian.agents.policy import PolicyAgent
        from guardian.agents.repository import RepositoryAgent
        from guardian.agents.risk import RiskFusionAgent
        from guardian.agents.security import SecurityAgent
        from guardian.agents.threat_simulation import ThreatSimulationAgent
        from guardian.agents.validation import ValidationAgent

        self.planner = PlannerAgent(tool_registry=self.tools, event_bus=self.event_bus, agent_registry=self.agent_registry)
        self.agent_registry.register("planner", self.planner)
        self.agent_registry.register("repository", RepositoryAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("business", BusinessAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("security", SecurityAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("architecture", ArchitectureAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("dependency", DependencyAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("threat_simulation", ThreatSimulationAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("policy", PolicyAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("risk_fusion", RiskFusionAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("patch", PatchGenerationAgent(tool_registry=self.tools, event_bus=self.event_bus))
        self.agent_registry.register("validation", ValidationAgent(tool_registry=self.tools, event_bus=self.event_bus))

        from guardian.orchestrator.checkpointer import get_checkpointer
        self.checkpointer = get_checkpointer()

        self.compiled_graph = build_workflow_graph(
            planner_agent=self.planner,
            tool_registry=self.tools,
            event_bus=self.event_bus,
            agent_registry=self.agent_registry,
            checkpointer=self.checkpointer
        )

    def execute(
        self,
        scan_id: str,
        repository_profile: Optional[Dict[str, Any]] = None,
        business_context: Optional[Dict[str, Any]] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        thread_id: Optional[str] = None
    ) -> AgentWorkflowState:
        """Executes the complete multi-agent workflow for a target repository scan."""
        import uuid
        thread_id = thread_id or str(uuid.uuid4())
        config = {"configurable": {"thread_id": thread_id}}
        
        t_start = time.perf_counter()

        initial_state = create_initial_state(
            scan_id=scan_id,
            repository_profile=repository_profile,
            business_context=business_context,
            policy_context=policy_context,
        )

        self.event_bus.publish(WorkflowStarted(scan_id=scan_id))

        # Invoke LangGraph StateGraph
        final_state: AgentWorkflowState = self.compiled_graph.invoke(initial_state, config=config)

        total_duration = time.perf_counter() - t_start

        # Update final Execution Metrics
        metrics = dict(final_state.get("execution_metrics", {}))
        metrics["total_execution_time"] = total_duration
        metrics["number_of_findings"] = len(final_state.get("findings", []))
        metrics["number_of_evidence_objects"] = len(final_state.get("evidence", []))
        final_state["execution_metrics"] = metrics

        self.event_bus.publish(
            WorkflowCompleted(
                scan_id=scan_id,
                total_findings=metrics["number_of_findings"],
                duration=total_duration
            )
        )

        return final_state

    def chat(self, message: str, thread_id: str) -> AgentWorkflowState:
        """Processes an interactive chat message via the RAG agent."""
        import asyncio
        from langchain_core.messages import HumanMessage
        config = {"configurable": {"thread_id": thread_id}}
        
        return asyncio.run(self.compiled_graph.ainvoke(
            {"scan_mode": "chat", "messages": [HumanMessage(content=message)]},
            config=config
        ))

