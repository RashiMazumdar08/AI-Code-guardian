import sys
import os
import json
import logging

cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

logging.basicConfig(level=logging.INFO)

from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, reset_scan_token_trackers, get_scan_token_tracker
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state
from backend.app.api.v1.scans import _SCANS_STORE
from backend.app.api.v1.agentic_scan import _adopt_deterministic_report, _build_agentic_analysis_result, _curated_state

def audit_real_workspace_run():
    print("=" * 80)
    print("DETAILED PIPELINE TRACE OF ARCHITECTURE AGENT ON REAL WORKSPACE SCAN")
    print("=" * 80)

    # Check if there is an existing deterministic scan in _SCANS_STORE
    print(f"\n1. DETERMINISTIC SCANS STORE COUNT: {len(_SCANS_STORE)}")
    
    # If no scan exists in _SCANS_STORE, run deterministic pipeline or build mock report matching real pipeline
    det_report = None
    if _SCANS_STORE:
        source_scan_id = list(_SCANS_STORE.keys())[-1]
        det_report = _SCANS_STORE[source_scan_id]
        print(f"   Adopting deterministic scan: {source_scan_id}")
    else:
        # Build report using repository profile of current workspace
        print("   No deterministic scan in store; using workspace profile fallback...")
        profile_dict = {
            "root": project_root,
            "primary_language": "Python",
            "detected_endpoints": ["/api/v1/agentic-scan", "/api/v1/scans", "/api/v1/business-intent", "/api/v1/reports", "/api/v1/findings"],
            "entry_points": ["backend/app/api/v1/agentic_scan.py", "backend/app/main.py"],
            "frameworks": ["FastAPI"],
            "total_files": 45,
            "auth_modules": ["Session/JWT Authentication Header"]
        }
        det_report = {
            "scan_id": "det_real_ws_001",
            "target": project_root,
            "repository": profile_dict,
            "scan": {"findings": [], "by_severity": {}},
            "evidence_items": []
        }

    # Step 1: Deterministic Adoption
    adopted = _adopt_deterministic_report(det_report)
    profile = adopted["repository_profile"]
    findings = adopted["findings"]
    evidence = adopted["evidence"]

    print("\n[STEP 1: ADOPTED DETERMINISTIC EVIDENCE]")
    print(f"  primary_language: {profile.get('primary_language')}")
    print(f"  detected_endpoints count: {len(profile.get('detected_endpoints', []))}")
    print(f"  entry_points count: {len(profile.get('entry_points', []))}")
    print(f"  frameworks: {profile.get('frameworks')}")
    print(f"  auth_modules: {profile.get('auth_modules')}")

    # Create initial LangGraph state
    scan_id = "agentic_real_audit_100"
    reset_scan_token_trackers()
    
    initial_state = create_initial_state(
        scan_id=scan_id,
        repository_profile=profile,
        scan_mode="full_scan",
        findings=findings,
        evidence=evidence
    )

    # Step 2: ArchitectureAgent Execution
    print("\n[STEP 2: ARCHITECTURE AGENT EXECUTION]")
    agent = ArchitectureAgent()
    
    # Let's inspect internal state variables right before LLM call inside _process
    endpoints = profile.get("detected_endpoints", [])
    entry_points = profile.get("entry_points", [])
    frameworks = profile.get("frameworks", [])

    service_boundaries = [f"service:{profile.get('primary_language', 'core')}"]
    auth_flows = initial_state.get("repository_context", {}).get("auth_modules", ["Session/JWT Authentication Header"])
    db_interactions = initial_state.get("repository_context", {}).get("database_layers", ["ORM Data Access Layer"])
    api_relationships = [f"API Endpoint: {ep}" for ep in endpoints[:5]]
    external_integrations = [f for f in frameworks if f in ["FastAPI", "Spring Boot", "NestJS", "Actix-web"]]

    trust_boundaries = []
    if endpoints or entry_points:
        trust_boundaries.append(
            "Public HTTP Gateway -> Application Controller "
            f"(evidenced by {len(endpoints)} detected endpoint(s) / "
            f"{len(entry_points)} entry point(s))"
        )
    if initial_state.get("repository_context", {}).get("database_layers"):
        trust_boundaries.append(
            "Application Layer -> Database "
            f"(evidenced by database layer(s): {', '.join(initial_state.get('repository_context', {}).get('database_layers', []))})"
        )

    arch_ev_items = [
        f"[E1] Service boundaries: {service_boundaries}",
        f"[E2] Auth flows: {auth_flows}",
        f"[E3] DB interactions: {db_interactions}",
        f"[E4] Trust boundaries: {trust_boundaries}",
        f"[E5] API Endpoints: {api_relationships[:5]}",
    ]
    try:
        from guardian.intent.matcher.rule_matcher import RuleMatcher
        ws_p = RuleMatcher._profiles_from_workspace()
        for p_idx, wp in enumerate(ws_p[:5]):
            if wp.controls:
                arch_ev_items.append(
                    f"[E{len(arch_ev_items)+1}] Component: {wp.file} | Function: {wp.function_name} | Controls: {','.join(wp.controls[:2])}"
                )
    except Exception as e:
        print("RuleMatcher exception:", e)

    evidence_block = "\n".join(arch_ev_items)
    print("Input Evidence Block:")
    print(evidence_block)

    # Step 3: LLM Token Admission & Request
    print("\n[STEP 3: TOKEN ADMISSION & LLM CALL]")
    cfg = LLMConfig.from_env()
    service = ReasoningGateway(config=cfg)
    service._enable_cache = False

    req = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id=scan_id,
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block=evidence_block,
        max_tokens=600,
        reasoning_effort="low",
    )
    prompt, truncated = service._build_prompt(req)
    print("Constructed Prompt Length:", len(prompt))

    ai_res = service.reason(req)
    print("Reasoning Result Available:", ai_res.available)
    print("Reasoning Result Error:", f"'{ai_res.error}'")
    if ai_res.response:
        print("LLM Response Raw:\n", ai_res.response.raw)
        print("Parsed Findings Count:", len(ai_res.response.findings))

    # Step 4: State after ArchitectureAgent
    new_state = agent._process(initial_state)
    insights_after_agent = new_state.get("ai_architecture_insights", [])
    grok_status = new_state.get("architecture_context", {}).get("grok_status")
    agent_reason = new_state.get("architecture_context", {}).get("agent_reason")

    print("\n[STEP 4: STATE AFTER ArchitectureAgent]")
    print("grok_status:", grok_status)
    print("agent_reason:", agent_reason)
    print("ai_architecture_insights count:", len(insights_after_agent))

    # Step 5: State after LangGraph merge_list passes
    from guardian.orchestrator.state import merge_list
    state_after_merge = merge_list(insights_after_agent, insights_after_agent)
    print("\n[STEP 5: LANGGRAPH STATE REDUCER (merge_list)]")
    print("ai_architecture_insights count after merge_list:", len(state_after_merge))

    # Step 6: Backend API Response
    curated = _curated_state(new_state)
    record = {"source_scan_id": "det_real_ws_001", "status": "completed", "scan_mode": "full_scan", "started_at": 1000.0}
    api_payload = _build_agentic_analysis_result(scan_id, record, curated)
    
    top_level_api = api_payload.get("ai_architecture_insights", [])
    nested_api = api_payload.get("architecture_analysis", {}).get("ai_architecture_insights", [])
    print("\n[STEP 6: BACKEND API PAYLOAD]")
    print("Top-level ai_architecture_insights count:", len(top_level_api))
    print("Nested architecture_analysis.ai_architecture_insights count:", len(nested_api))

    # Step 7: Frontend Props and Component rendering check
    print("\n[STEP 7: FRONTEND PROPS & RENDER EVALUATION]")
    # In AIArchitectureAnalysisSection.tsx:
    # combinedInsights = aiArchitectureInsights.length > 0 ? aiArchitectureInsights : architectureAnalysis?.ai_architecture_insights || []
    combined_insights = top_level_api if len(top_level_api) > 0 else nested_api
    print("combinedInsights count:", len(combined_insights))
    if len(combined_insights) == 0:
        if grok_status in ["COMPLETED", "SKIPPED", None]:
            print("UI RENDER PATH: Renders 'No AI Architecture Vulnerabilities Flagged' Banner!")
        elif grok_status == "SKIPPED_BUDGET":
            print("UI RENDER PATH: Renders 'SKIPPED (Token Budget Limit)' Callout!")
        elif grok_status == "PROVIDER_DAILY_QUOTA":
            print("UI RENDER PATH: Renders 'DAILY QUOTA EXHAUSTED' Callout!")
        elif grok_status in ["FAILED", "UNAVAILABLE", "PROVIDER_UNAVAILABLE"]:
            print("UI RENDER PATH: Renders 'SERVICE UNAVAILABLE' Callout!")
    else:
        print(f"UI RENDER PATH: Renders {len(combined_insights)} Architecture Insight Cards!")

if __name__ == "__main__":
    audit_real_workspace_run()
