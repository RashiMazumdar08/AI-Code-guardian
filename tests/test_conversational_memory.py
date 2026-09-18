"""Tests for LangGraph Conversational Memory and Redis Checkpointer."""
import uuid
from typing import Any
from unittest.mock import patch

import fakeredis
import pytest
from langchain_core.messages import HumanMessage

from guardian.orchestrator.checkpointer import get_checkpointer
from guardian.orchestrator.workflow import OrchestratorWorkflow


@pytest.fixture
def mock_redis():
    """Mock RedisManager.client with fakeredis and disable agent runs."""
    fake_client = fakeredis.FakeRedis(decode_responses=True)
    with patch("guardian.cache.redis_manager.redis.Redis", return_value=fake_client), \
         patch("guardian.orchestrator.planner.PlannerAgent.run", side_effect=lambda s: s), \
         patch("guardian.agents.repository.agent.RepositoryAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.business.agent.BusinessAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.security.agent.SecurityAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.architecture.agent.ArchitectureAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.dependency.agent.DependencyAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.threat_simulation.agent.ThreatSimulationAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.policy.agent.PolicyAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.risk.agent.RiskFusionAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.patch.agent.PatchGenerationAgent.run", side_effect=lambda s: s, create=True), \
         patch("guardian.agents.validation.agent.ValidationAgent.run", side_effect=lambda s: s, create=True):
        yield fake_client


def test_conversational_memory_persistence(mock_redis):
    thread_id = f"test-session-{uuid.uuid4()}"
    
    workflow = OrchestratorWorkflow()
    
    # Run 1
    state1 = workflow.execute(scan_id="scan-1", thread_id=thread_id)
    assert state1["scan_id"] == "scan-1"
    
    config = {"configurable": {"thread_id": thread_id}}
    workflow.compiled_graph.update_state(config, {"messages": [HumanMessage(content="Hello", id="msg1")]})
    
    # Rehydrate
    state_after_update = workflow.compiled_graph.get_state(config).values
    assert len(state_after_update["messages"]) == 1
    assert state_after_update["messages"][0].content == "Hello"


def test_conversational_memory_isolation(mock_redis):
    workflow = OrchestratorWorkflow()
    
    thread1 = f"thread-{uuid.uuid4()}"
    thread2 = f"thread-{uuid.uuid4()}"
    
    config1 = {"configurable": {"thread_id": thread1}}
    config2 = {"configurable": {"thread_id": thread2}}
    
    # Execute to initialize states
    workflow.execute(scan_id="scan-1", thread_id=thread1)
    workflow.execute(scan_id="scan-2", thread_id=thread2)
    
    # Update thread 1
    workflow.compiled_graph.update_state(config1, {"messages": [HumanMessage(content="Message for 1", id="msg2")]})
    
    state1 = workflow.compiled_graph.get_state(config1).values
    state2 = workflow.compiled_graph.get_state(config2).values
    
    assert len(state1.get("messages", [])) == 1
    assert state1["messages"][0].content == "Message for 1"
    assert len(state2.get("messages", [])) == 0


def test_message_truncation(mock_redis):
    workflow = OrchestratorWorkflow()
    thread_id = f"test-trunc-{uuid.uuid4()}"
    config = {"configurable": {"thread_id": thread_id}}
    
    workflow.execute(scan_id="scan-1", thread_id=thread_id)
    
    # Add 15 messages (over the 10 limit)
    messages = [HumanMessage(content=f"Msg {i}", id=f"msg_{i}") for i in range(15)]
    workflow.compiled_graph.update_state(config, {"messages": messages})
    
    state_before = workflow.compiled_graph.get_state(config).values
    assert len(state_before["messages"]) == 15
    
    # Execute again to trigger trim_messages node
    workflow.compiled_graph.invoke({"scan_id": "scan-1"}, config=config)
    
    state_after = workflow.compiled_graph.get_state(config).values
    assert len(state_after["messages"]) == 10
    assert state_after["messages"][-1].content == "Msg 14"
