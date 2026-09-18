"""Tests for the Interactive RAG Agent and LangGraph dynamic routing."""
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from langchain_core.messages import AIMessage, HumanMessage

from guardian.orchestrator.state import create_initial_state
from guardian.orchestrator.workflow import OrchestratorWorkflow


@pytest.fixture
def mock_redis():
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


def test_route_to_planner(mock_redis):
    workflow = OrchestratorWorkflow()
    thread_id = str(uuid.uuid4())
    state = workflow.execute(scan_id="scan-1", thread_id=thread_id)
    # Planner was executed and scan_mode is full_scan
    assert state.get("scan_mode") == "full_scan"
    assert state.get("scan_id") == "scan-1"


@patch("guardian.agents.chat.agent.InteractiveChatAgent")
def test_route_to_chat(mock_chat_cls, mock_redis):
    mock_instance = MagicMock()
    async def mock_run(state, config=None):
        msgs = list(state.get("messages", []))
        msgs.append(AIMessage(content="Hello from Chat Agent!"))
        return {"messages": msgs, "scan_mode": "chat"}
    mock_instance.run = mock_run
    mock_instance.tools = []
    mock_chat_cls.return_value = mock_instance

    workflow = OrchestratorWorkflow()
    thread_id = str(uuid.uuid4())
    
    # Send a chat message
    state = workflow.chat("How does authentication work?", thread_id=thread_id)
    
    assert state.get("scan_mode") == "chat"
    assert len(state["messages"]) >= 2
    
    messages = state["messages"]
    assert isinstance(messages[-2], HumanMessage)
    assert messages[-2].content == "How does authentication work?"
    assert isinstance(messages[-1], AIMessage)
    assert messages[-1].content == "Hello from Chat Agent!"


@patch("guardian.agents.chat.agent.InteractiveChatAgent")
def test_tool_execution_loop(mock_chat_cls, mock_redis):
    mock_instance = MagicMock()
    async def mock_run(state, config=None):
        msgs = list(state.get("messages", []))
        tool_call = {
            "name": "semantic_search",
            "args": {"query": "auth", "limit": 5},
            "id": "call_123"
        }
        msgs.append(AIMessage(content="", tool_calls=[tool_call]))
        msgs.append(AIMessage(content="Auth uses JWT."))
        return {"messages": msgs, "scan_mode": "chat"}
    mock_instance.run = mock_run
    mock_instance.tools = []
    mock_chat_cls.return_value = mock_instance

    workflow = OrchestratorWorkflow()
    thread_id = str(uuid.uuid4())
    
    state = workflow.chat("Find auth", thread_id=thread_id)
    
    messages = state["messages"]
    assert len(messages) >= 2
    assert mock_chat_cls.called
    
    final_message = messages[-1]
    assert isinstance(final_message, AIMessage)
    assert final_message.content == "Auth uses JWT."
