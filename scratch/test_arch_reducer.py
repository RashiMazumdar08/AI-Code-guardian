import sys
import os
import json

# Ensure project root is in sys.path
cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state, merge_list
from guardian.reasoning.schemas import ReasoningFinding
from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result, _curated_state

def test_reducer_and_duplication():
    print("=== ARCHITECTURE AGENT INSIGHT CREATION & REDUCER AUDIT ===")
    
    # 1. Simulate what ArchitectureAgent produces when Grok/Gemini returns 1 finding
    rf = ReasoningFinding(
        evidence_ids=["E1"],
        category="architecture",
        severity="High",
        confidence=0.9,
        reason="The evidence shows a public HTTP gateway directly connected to the backend handler without authentication.",
        recommendation="Enforce API gateway authentication.",
        title="Public HTTP Gateway Direct Connection",
        file="backend/app/api/v1/agentic_scan.py",
        line=55,
        function="_build_agentic_analysis_result"
    )
    
    raw_insight_dict = rf.to_dict()
    print("\n1. RAW INSIGHT DICT RETURNED BY rf.to_dict():")
    print(json.dumps(raw_insight_dict, indent=2))
    
    # Check ID keys in raw_insight_dict
    id_keys = ["id", "finding_id", "insight_id", "patch_id", "rule_id"]
    present_id_keys = {k: raw_insight_dict.get(k) for k in id_keys if k in raw_insight_dict}
    print(f"\nID keys present in raw_insight_dict: {present_id_keys}")
    
    # 2. Test merge_list reducer behavior across multiple graph node updates
    print("\n2. LANGGRAPH REDUCER (merge_list) MULTI-PASS SIMULATION:")
    
    state_insights = [raw_insight_dict] # After ArchitectureAgent runs
    print(f"State after ArchitectureAgent node: count = {len(state_insights)}")
    
    # Node update 1 (e.g. from parallel merge or next node update)
    node_update_1 = [raw_insight_dict]
    state_insights = merge_list(state_insights, node_update_1)
    print(f"State after Node Pass 1 (merge_list): count = {len(state_insights)}")
    
    # Node update 2 (e.g. from threat_simulation node or risk_fusion node returning state)
    node_update_2 = [raw_insight_dict]
    state_insights = merge_list(state_insights, node_update_2)
    print(f"State after Node Pass 2 (merge_list): count = {len(state_insights)}")

    # Node update 3 (e.g. from policy node returning state)
    node_update_3 = [raw_insight_dict]
    state_insights = merge_list(state_insights, node_update_3)
    print(f"State after Node Pass 3 (merge_list): count = {len(state_insights)}")

    # Node update 4 (e.g. from validation node returning state)
    node_update_4 = [raw_insight_dict]
    state_insights = merge_list(state_insights, node_update_4)
    print(f"State after Node Pass 4 (merge_list): count = {len(state_insights)}")

    # 3. Backend API payload construction
    print("\n3. BACKEND API PAYLOAD BUILDER (_build_agentic_analysis_result):")
    mock_state = {
        "scan_id": "scan_audit_1",
        "active_agent": "validation",
        "completed_agents": ["planner", "repository", "security", "architecture", "dependency", "threat_simulation", "policy", "risk_fusion", "validation"],
        "ai_architecture_insights": state_insights,
        "architecture_context": {
            "service_boundaries": ["service:python"],
            "trust_boundaries": ["Public HTTP Gateway -> Application Controller"]
        }
    }
    curated = _curated_state(mock_state)
    record = {"source_scan_id": "det_scan_1", "status": "completed", "scan_mode": "full_scan", "started_at": 100.0}
    api_result = _build_agentic_analysis_result("scan_audit_1", record, curated)
    
    top_level = api_result.get("ai_architecture_insights", [])
    nested = api_result.get("architecture_analysis", {}).get("ai_architecture_insights", [])
    print(f"Top-level 'ai_architecture_insights' count in API payload: {len(top_level)}")
    print(f"Nested 'architecture_analysis.ai_architecture_insights' count in API payload: {len(nested)}")
    
    # 4. Simulated Frontend Render Count
    print("\n4. FRONTEND RENDERED CARDS COUNT:")
    # In SecurityWorkbench.tsx:
    # aiArchitectureInsights = agentic.result?.ai_architecture_insights || ...
    # In AIArchitectureAnalysisSection.tsx:
    # combinedInsights = aiArchitectureInsights.length > 0 ? aiArchitectureInsights : ...
    # combinedInsights.map(...) renders 1 card per item
    rendered_cards = len(top_level)
    print(f"Total cards rendered in AIArchitectureAnalysisSection left pane: {rendered_cards}")

if __name__ == "__main__":
    test_reducer_and_duplication()
