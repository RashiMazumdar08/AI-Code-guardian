"""
AI Code Guardian v3 — Orchestrator Unit Tests
=============================================
Tests for shared workflow state, StateGraph, PlannerAgent, AgentRegistry,
ToolRegistry, EventBus, AgentTrace, and ExecutionMetrics.
"""
from __future__ import annotations

import pytest

from guardian.orchestrator import (
    AgentRegistry,
    AgentTrace,
    AgentWorkflowState,
    BaseTool,
    EventBus,
    ExecutionMetrics,
    ExecutionPlan,
    OrchestratorWorkflow,
    PlannerAgent,
    PlannerCompleted,
    ToolRegistry,
    WorkflowCompleted,
    WorkflowStarted,
    build_workflow_graph,
    create_initial_state,
)


def test_shared_workflow_state_initialization():
    state = create_initial_state(
        scan_id="scan-123",
        repository_profile={"primary_language": "Python"},
        business_context={"domain": "fintech"},
        policy_context={"frameworks": ["OWASP_TOP_10"]},
    )

    assert state["scan_id"] == "scan-123"
    assert state["repository_profile"]["primary_language"] == "Python"
    assert state["business_context"]["domain"] == "fintech"
    assert state["policy_context"]["frameworks"] == ["OWASP_TOP_10"]
    assert state["active_agent"] == "IDLE"

    # Verify all 22 required state keys are present
    required_keys = [
        "scan_id", "repository_profile", "repository_graph", "semantic_context",
        "business_context", "policy_context", "knowledge_context", "retrieved_documents",
        "current_task", "execution_plan", "active_agent", "completed_agents",
        "pending_agents", "findings", "evidence", "risk_scores", "validation_results",
        "patches", "reports", "agent_trace", "execution_metrics"
    ]
    for key in required_keys:
        assert key in state, f"Missing required state key: {key}"


def test_event_bus():
    bus = EventBus()
    received_events = []

    def on_started(evt):
        received_events.append(evt)

    bus.subscribe(WorkflowStarted, on_started)
    evt = WorkflowStarted(scan_id="scan-456")
    bus.publish(evt)

    assert len(received_events) == 1
    assert received_events[0].scan_id == "scan-456"

    bus.unsubscribe(WorkflowStarted, on_started)
    bus.publish(WorkflowStarted(scan_id="scan-789"))
    assert len(received_events) == 1


def test_tool_registry():
    registry = ToolRegistry()

    assert "knowledge_tool" in registry.list_tools()
    assert "policy_tool" in registry.list_tools()
    assert "business_intent_tool" in registry.list_tools()

    class CustomTool(BaseTool):
        name = "custom_test_tool"
        description = "Custom test tool"

        def run(self, **kwargs):
            return {"status": "success", "echo": kwargs.get("data")}

    registry.register(CustomTool())
    assert "custom_test_tool" in registry.list_tools()

    res = registry.execute("custom_test_tool", data="hello")
    assert res["status"] == "success"
    assert res["echo"] == "hello"
    assert "_tool_runtime" in res


def test_agent_registry():
    registry = AgentRegistry()

    class MockSecurityAgent:
        name = "security"

    registry.register("security", MockSecurityAgent)

    assert registry.has_agent("security")
    assert registry.get("security") == MockSecurityAgent
    assert "security" in registry.list_agents()

    registry.unregister("security")
    assert not registry.has_agent("security")


def test_planner_agent():
    bus = EventBus()
    planner_events = []
    bus.subscribe(PlannerCompleted, lambda e: planner_events.append(e))

    tools = ToolRegistry()
    planner = PlannerAgent(tool_registry=tools, event_bus=bus)

    state = create_initial_state(
        scan_id="scan-999",
        repository_profile={"frameworks": ["FastAPI"]},
        business_context={"domain": "healthcare", "criticality": "CRITICAL"},
        policy_context={"frameworks": ["NIST_800_53"]},
    )

    updated_state = planner.run(state)

    assert updated_state["active_agent"] == "planner"
    assert "planner" in updated_state["completed_agents"]

    plan = updated_state["execution_plan"]
    assert plan["priority"] == "HIGH"
    assert "repository" in plan["agent_order"]
    assert len(plan["agent_order"]) == 10

    # Verify agent trace
    assert len(updated_state["agent_trace"]) == 1
    trace = updated_state["agent_trace"][0]
    assert trace["agent_name"] == "planner"
    assert trace["confidence"] == 0.95

    # Verify event published
    assert len(planner_events) == 1
    assert planner_events[0].scan_id == "scan-999"


def test_stategraph_workflow_execution():
    bus = EventBus()
    events = []
    bus.subscribe(WorkflowStarted, lambda e: events.append("started"))
    bus.subscribe(WorkflowCompleted, lambda e: events.append("completed"))

    orchestrator = OrchestratorWorkflow(event_bus=bus)

    final_state = orchestrator.execute(
        scan_id="scan-full-test",
        repository_profile={"primary_language": "Python"},
        business_context={"domain": "fintech"},
        policy_context={"frameworks": ["OWASP_TOP_10"]},
    )

    assert final_state["scan_id"] == "scan-full-test"
    assert final_state["active_agent"] == "validation"
    assert "planner" in final_state["completed_agents"]
    assert "validation" in final_state["completed_agents"]
    assert final_state["execution_plan"]["priority"] == "NORMAL"

    metrics = final_state["execution_metrics"]
    assert metrics["total_execution_time"] > 0.0
    assert "planner" in metrics["agent_runtime"]

    assert events == ["started", "completed"]
