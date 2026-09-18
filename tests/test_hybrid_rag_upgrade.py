"""
Unit & Integration Tests for RAG Engine Upgrade
===============================================
Tests parallel execution under asyncio.gather, Reciprocal Rank Fusion (k=60) math accuracy,
ContextBudgetManager token limits & evidence prioritization, and Requirement grounding "unresolved" fallbacks.
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from guardian.knowledge.retrieval.budget_manager import ContextBudgetManager
from guardian.knowledge.retrieval.hybrid_engine import ParallelHybridEngine
from guardian.knowledge.services.requirement_service import RequirementService, RequirementConstraint
from guardian.agents.chat.agent import InteractiveChatAgent
from guardian.orchestrator.tools import ToolRegistry
from guardian.orchestrator.events import EventBus


def test_rrf_math_accuracy():
    """Validates Reciprocal Rank Fusion (RRF, k=60) mathematical calculation."""
    engine = ParallelHybridEngine(rrf_k=60)
    
    list_a = [
        {"id": "D1", "title": "Doc 1", "content": "Content 1"},
        {"id": "D2", "title": "Doc 2", "content": "Content 2"},
        {"id": "D3", "title": "Doc 3", "content": "Content 3"}
    ]
    list_b = [
        {"id": "D2", "title": "Doc 2", "content": "Content 2"},
        {"id": "D1", "title": "Doc 1", "content": "Content 1"},
        {"id": "D4", "title": "Doc 4", "content": "Content 4"}
    ]
    
    fused = engine.apply_rrf([list_a, list_b])
    
    # Expected RRF scores with k=60:
    # D1: 1/(60+1) + 1/(60+2) = 1/61 + 1/62 = 0.0163934 + 0.016129 = 0.0325224
    # D2: 1/(60+2) + 1/(60+1) = 1/62 + 1/61 = 0.0325224
    # D3: 1/(60+3) = 1/63 = 0.015873
    # D4: 1/(60+3) = 1/63 = 0.015873
    
    doc_scores = {d["id"]: round(d["rrf_score"], 6) for d in fused}
    expected_top_score = round(1/61 + 1/62, 6)
    
    assert doc_scores["D1"] == expected_top_score
    assert doc_scores["D2"] == expected_top_score
    assert doc_scores["D3"] == round(1/63, 6)
    assert doc_scores["D4"] == round(1/63, 6)
    assert fused[0]["id"] in ["D1", "D2"]
    assert fused[1]["id"] in ["D1", "D2"]


def test_context_budget_manager_prioritization_and_truncation():
    """Verifies ContextBudgetManager token truncation and Evidence ID priority."""
    budget_mgr = ContextBudgetManager(max_tokens=100, max_chunks=2, chars_per_token=4)
    
    items = [
        {"id": "gen1", "title": "Generic Policy", "content": "A" * 150},
        {"id": "ev1", "title": "Vulnerability Evidence", "content": "Finding in auth.py [Evidence E1]", "evidence_ids": ["E1"]},
        {"id": "gen2", "title": "Generic Standard", "content": "B" * 150}
    ]
    
    result = budget_mgr.trim_and_format(items, active_evidence_ids=["E1"])
    
    assert len(result["included_items"]) <= 2
    assert result["included_items"][0]["id"] == "ev1"
    assert "E1" in result["evidence_ids_included"]
    assert len(result["dropped_items"]) >= 1


def test_parallel_execution_asyncio_gather():
    """Verifies parallel dual-path execution under asyncio.gather."""
    async def _test():
        mock_qdrant = MagicMock()
        mock_qdrant.search.return_value = [{"id": "vec1", "content": "vector result"}]
        
        mock_graph = MagicMock()
        mock_graph.find_nodes_by_label.return_value = []
        
        engine = ParallelHybridEngine(qdrant_manager=mock_qdrant, graph_manager=mock_graph)
        
        res = await engine.hybrid_search(query="SQL injection auth", top_k=5)
        
        assert res["query"] == "SQL injection auth"
        assert "formatted_context" in res
        assert res["used_tokens"] > 0
        assert mock_qdrant.search.called

    asyncio.run(_test())


def test_requirement_grounding_unresolved_fallback():
    """Verifies that missing evidence triggers unresolved status."""
    service = RequirementService()
    
    # 1. No evidence provided
    res1 = service.evaluate_requirement_satisfaction("REQ-AUTH-01", "Does the system enforce MFA?")
    assert res1["status"] == "unresolved"
    assert res1["verified"] is False
    
    # 2. Irrelevant evidence provided
    res2 = service.evaluate_requirement_satisfaction(
        "REQ-AUTH-01",
        "Does the system enforce MFA?",
        evidence_items=[{"text": "Unrelated CSS layout styling snippet"}]
    )
    assert res2["status"] == "unresolved"
    assert res2["verified"] is False


def test_interactive_chat_agent_tools():
    """Verifies InteractiveChatAgent has hybrid_search registered in tools."""
    tool_registry = ToolRegistry()
    event_bus = EventBus()
    
    with patch("guardian.agents.chat.agent.ChatOpenAI"):
        agent = InteractiveChatAgent(tool_registry=tool_registry, event_bus=event_bus)
        tool_names = [t.name for t in agent.tools]
        
        assert "hybrid_search" in tool_names
        assert "semantic_search" in tool_names
        assert "repository_graph_query" in tool_names
        assert "fetch_evidence" in tool_names
        assert "get_scan_findings" in tool_names
        assert "get_scan_patches" in tool_names
