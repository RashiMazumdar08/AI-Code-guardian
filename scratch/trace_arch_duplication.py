import sys
import os
import json
import logging

# Ensure project root is in sys.path
cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trace_arch")

def run_trace():
    print("=" * 60)
    print("STARTING ARCHITECTURE AGENT DUPLICATION TRACE")
    print("=" * 60)

    # 1. Inspect RuleMatcher._profiles_from_workspace()
    try:
        from guardian.intent.matcher.rule_matcher import RuleMatcher
        ws_p = RuleMatcher._profiles_from_workspace()
        print(f"\n[STAGE 2: CANDIDATE EXTRACTION]")
        print(f"Total raw profiles extracted by RuleMatcher._profiles_from_workspace(): {len(ws_p)}")
        for idx, wp in enumerate(ws_p):
            print(f"  Candidate [{idx+1}]: file={getattr(wp, 'file', '')}, fn={getattr(wp, 'function_name', '')}, controls={getattr(wp, 'controls', [])}")
    except Exception as e:
        print(f"Error inspecting RuleMatcher: {e}")

    # 2. Test ArchitectureAgent execution directly
    print(f"\n[STAGE 1 & 3: ARCHITECTURE AGENT & REASONING]")
    from guardian.agents.architecture.agent import ArchitectureAgent
    from guardian.orchestrator.state import create_initial_state, merge_list

    agent = ArchitectureAgent()
    init_state = create_initial_state(scan_id="test_arch_scan_100")
    
    # Run ArchitectureAgent once
    state_after_arch = agent._process(init_state)
    
    arch_insights = state_after_arch.get("ai_architecture_insights", [])
    print(f"ArchitectureAgent._process returned ai_architecture_insights count: {len(arch_insights)}")
    for idx, insight in enumerate(arch_insights):
        print(f"  Insight [{idx+1}]:")
        print(f"    Keys present: {list(insight.keys())}")
        print(f"    id: {insight.get('id')}")
        print(f"    finding_id: {insight.get('finding_id')}")
        print(f"    insight_id: {insight.get('insight_id')}")
        print(f"    title: {insight.get('title')}")
        print(f"    severity: {insight.get('severity')}")
        print(f"    file: {insight.get('file')}")
        print(f"    function: {insight.get('function')}")
        print(f"    line: {insight.get('line')}")

    # 3. Test Reducer logic in state.py
    print(f"\n[STAGE 3: REDUCER TEST IN guardian/orchestrator/state.py]")
    print("Testing merge_list with two state updates containing the SAME insight dicts returned by ArchitectureAgent:")
    list_a = [dict(item) for item in arch_insights]
    list_b = [dict(item) for item in arch_insights]
    merged = merge_list(list_a, list_b)
    print(f"  list_a count: {len(list_a)}")
    print(f"  list_b count: {len(list_b)}")
    print(f"  merged count (using merge_list): {len(merged)}")
    print(f"  Did merge_list deduplicate? {'NO - DUPLICATED!' if len(merged) == len(list_a) + len(list_b) and len(list_a) > 0 else 'YES'}")

    # 4. Run OrchestratorWorkflow / LangGraph flow trace
    print(f"\n[STAGE 4 & 5: FULL LANGGRAPH SCAN TRACE]")
    from guardian.orchestrator.workflow import OrchestratorWorkflow
    from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result, _curated_state

    wf = OrchestratorWorkflow()
    # Create initial state with a dummy profile and scan_mode='full_scan'
    scan_state = create_initial_state(
        scan_id="test_arch_scan_100",
        repository_profile={"primary_language": "python", "detected_endpoints": ["/api/v1/agentic-scan"], "entry_points": ["backend/app/api/v1/agentic_scan.py"]},
        scan_mode="full_scan"
    )
    
    # We can inspect the compiled graph
    config = {"configurable": {"thread_id": "test_arch_scan_100"}}
    
    arch_exec_count = 0
    state_snapshots = []
    
    try:
        for s in wf.compiled_graph.stream(scan_state, config=config, stream_mode="values"):
            active = s.get("active_agent")
            current_insights = s.get("ai_architecture_insights", [])
            print(f"  [Superstep] active_agent={active} | completed={s.get('completed_agents')} | ai_arch_insights_len={len(current_insights)}")
            state_snapshots.append(s)
    except Exception as e:
        print(f"Error during graph stream: {e}")

    if state_snapshots:
        final_state = state_snapshots[-1]
        curated = _curated_state(final_state)
        dummy_record = {
            "source_scan_id": "det_scan_1",
            "status": "completed",
            "scan_mode": "full_scan",
            "started_at": 1000.0,
            "repository_profile": {"primary_language": "python"}
        }
        res = _build_agentic_analysis_result("test_arch_scan_100", dummy_record, curated)
        
        top_insights = res.get("ai_architecture_insights", [])
        arch_analysis = res.get("architecture_analysis", {})
        nested_insights = arch_analysis.get("ai_architecture_insights", [])
        
        print(f"\n[STAGE 5: BACKEND API PAYLOAD]")
        print(f"  Top-level 'ai_architecture_insights' count: {len(top_insights)}")
        print(f"  Nested 'architecture_analysis.ai_architecture_insights' count: {len(nested_insights)}")

if __name__ == "__main__":
    run_trace()
