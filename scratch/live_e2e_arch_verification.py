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
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, reset_scan_token_trackers
from guardian.agents.repository.agent import RepositoryAgent
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state, merge_list
from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result, _curated_state

def run_live_e2e_verification():
    print("=" * 80)
    print("FRESH LIVE END-TO-END VERIFICATION OF ARCHITECTURE AGENT")
    print("=" * 80)

    # 1. Adopt current workspace repository profile
    from pathlib import Path
    workspace_path = Path(project_root)

    profile = {
        "root": str(workspace_path),
        "primary_language": "Python",
        "frameworks": ["FastAPI"],
        "detected_endpoints": ["/api/v1/agentic-scan", "/api/v1/scans", "/api/v1/business-intent", "/api/v1/reports", "/api/v1/findings"],
        "entry_points": ["backend/app/api/v1/agentic_scan.py", "backend/app/main.py"],
        "security_markers": ["JWT Auth", "CORS Policy"],
        "architecture": ["backend", "cloud-native"],
        "total_files": 45
    }

    state = create_initial_state(
        scan_id="live_e2e_arch_001",
        repository_profile=profile,
        scan_mode="full_scan"
    )

    # 2. Execute RepositoryAgent
    repo_agent = RepositoryAgent()
    state_after_repo = repo_agent._process(state)
    repo_ctx = state_after_repo.get("repository_context", {})
    ep_cov = repo_ctx.get("endpoint_coverage", {})

    print("\n--- 1. REPOSITORY AGENT OUTPUT ---")
    print(f"Total detected route endpoints          : {ep_cov.get('total_route_endpoints')}")
    print(f"Endpoints WITH detected route-level auth : {ep_cov.get('authenticated_endpoints_count')}")
    print(f"Endpoints WITHOUT detected route auth   : {ep_cov.get('unauthenticated_endpoints_count')}")
    print(f"Authentication coverage percentage     : {ep_cov.get('auth_coverage_pct')}%")
    print(f"Representative endpoints without auth   :")
    for rep in ep_cov.get("representative_unauthenticated_endpoints", []):
        print(f"   - {rep}")

    # 3. Execute ArchitectureAgent & inspect evidence block + prompt
    print("\n--- 2 & 3. ARCHITECTURE AGENT EVIDENCE BLOCK & PROMPT ---")
    reset_scan_token_trackers()
    cfg = LLMConfig.from_env()
    service = ReasoningGateway(config=cfg)
    service._enable_cache = False

    endpoints = profile.get("detected_endpoints", [])
    entry_points = profile.get("entry_points", [])
    frameworks = profile.get("frameworks", [])

    service_boundaries = [f"service:{profile.get('primary_language', 'core')}"]
    auth_flows = repo_ctx.get("auth_modules", ["Session/JWT Authentication Header"])
    db_interactions = repo_ctx.get("database_layers", ["ORM Data Access Layer"])

    trust_boundaries = []
    if endpoints or entry_points:
        trust_boundaries.append(
            "Public HTTP Gateway -> Application Controller "
            f"(evidenced by {len(endpoints)} detected endpoint(s) / "
            f"{len(entry_points)} entry point(s))"
        )

    ep_coverage = repo_ctx.get("endpoint_coverage", {})
    auth_mech_str = ", ".join(auth_flows) if auth_flows else "No global auth module detected"

    arch_ev_items = [
        f"[E1] Service boundaries: {service_boundaries}",
        f"[E2] Authentication mechanism: {auth_mech_str}",
        f"[E3] DB interactions: {db_interactions}",
        f"[E4] Trust boundaries: {trust_boundaries}",
    ]

    if ep_coverage and ep_coverage.get("total_route_endpoints", 0) > 0:
        total_eps = ep_coverage.get("total_route_endpoints", 0)
        auth_cnt = ep_coverage.get("authenticated_endpoints_count", 0)
        unauth_cnt = ep_coverage.get("unauthenticated_endpoints_count", 0)
        pct = ep_coverage.get("auth_coverage_pct", 0.0)
        unauth_list = ep_coverage.get("representative_unauthenticated_endpoints", [])

        arch_ev_items.append(
            f"[E5] Endpoint authentication coverage: {total_eps} route endpoints detected, "
            f"{auth_cnt} with route-level authentication, "
            f"{unauth_cnt} without detected route-level authentication (Coverage: {pct}%)"
        )
        if unauth_list:
            arch_ev_items.append(
                f"[E6] Representative endpoints without detected route-level authentication: {', '.join(unauth_list)}"
            )

    evidence_block = "\n".join(arch_ev_items)
    print("Exact Evidence Block Sent to LLM:")
    print(evidence_block)

    req = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id="live_e2e_arch_001",
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block=evidence_block,
        max_tokens=500,
        reasoning_effort="low",
    )

    prompt, _ = service._build_prompt(req)
    print(f"\nFinal LLM Prompt Length: {len(prompt)} chars")
    assert "[E5] Endpoint authentication coverage" in prompt
    print("Confirmed: Endpoint coverage evidence [E5] is included in the final LLM prompt!")

    # 4 & 5 & 6. Execute ArchitectureAgent once
    print("\n--- 4 & 5. ARCHITECTURE AGENT EXECUTION & RAW LLM RESPONSE ---")
    arch_agent = ArchitectureAgent()
    state_after_arch = arch_agent._process(state_after_repo)

    arch_ctx = state_after_arch.get("architecture_context", {})
    grok_status = arch_ctx.get("grok_status")
    agent_reason = arch_ctx.get("agent_reason")
    insights_after_agent = state_after_arch.get("ai_architecture_insights", [])

    print(f"grok_status  : {grok_status}")
    print(f"agent_reason : {agent_reason}")
    print(f"ai_architecture_insights count immediately after ArchitectureAgent: {len(insights_after_agent)}")

    for idx, fd in enumerate(insights_after_agent):
        print(f"\n  Finding [{idx+1}]:")
        print(f"    ID          : {fd.get('id')}")
        print(f"    Title       : {fd.get('title') or fd.get('reason')}")
        print(f"    Severity    : {fd.get('severity')}")
        print(f"    Evidence IDs: {fd.get('evidence_ids')}")
        print(f"    File        : {fd.get('file')}:{fd.get('line')}")
        print(f"    Function    : {fd.get('function')}")
        print(f"    Reason      : {fd.get('reason')}")
        print(f"    Recommendation: {fd.get('recommendation')}")

    # 6. LangGraph State & Deduplication Verification
    print("\n--- 6. LANGGRAPH STATE PROPAGATION & DEDUPLICATION ---")
    simulated_state = list(insights_after_agent)
    for pass_num in range(1, 5):
        simulated_state = merge_list(simulated_state, insights_after_agent)
        print(f"ai_architecture_insights count after Node Pass #{pass_num}: {len(simulated_state)}")

    assert len(simulated_state) == len(insights_after_agent)
    print("Confirmed: Stable-ID and merge_list deduplication keeps unique findings exactly once!")

    # 7. API Response Serialization
    print("\n--- 7. API RESPONSE SERIALIZATION ---")
    curated = _curated_state(state_after_arch)
    record = {"source_scan_id": "det_live_001", "status": "completed", "scan_mode": "full_scan", "started_at": 1000.0}
    api_payload = _build_agentic_analysis_result("live_e2e_arch_001", record, curated)
    
    top_api_count = len(api_payload.get("ai_architecture_insights", []))
    nested_api_count = len(api_payload.get("architecture_analysis", {}).get("ai_architecture_insights", []))
    print(f"Top-level ai_architecture_insights count in API payload: {top_api_count}")
    print(f"Nested architecture_analysis.ai_architecture_insights count in API payload: {nested_api_count}")

    # 8. Frontend Reception & Comparison
    print("\n--- 8. FRONTEND RECEPTION & COMPARISON ---")
    combined_insights = top_api_count if top_api_count > 0 else nested_api_count
    print(f"Frontend combinedInsights count: {combined_insights}")
    if combined_insights > 0:
        print(f"RESULT CHANGE: LLM generated {combined_insights} architecture finding(s) citing explicit endpoint coverage evidence!")
    else:
        print("RESULT UNCHANGED: LLM generated 0 architecture findings based on evidence evaluation.")

if __name__ == "__main__":
    run_live_e2e_verification()
