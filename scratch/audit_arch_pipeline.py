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
logger = logging.getLogger("audit_arch_pipeline")

def run_pipeline_audit():
    print("=" * 70)
    print("STARTING ARCHITECTURE AGENT PIPELINE AUDIT")
    print("=" * 70)

    from guardian.llm.config import LLMConfig
    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
    from guardian.agents.architecture.agent import ArchitectureAgent
    from guardian.orchestrator.state import create_initial_state

    cfg = LLMConfig.from_env()
    print(f"\n[LLM CONFIGURATION]")
    print(f"Provider: {cfg.provider}")
    print(f"Model: {cfg.model}")
    print(f"Is Configured: {cfg.is_configured}")
    print(f"Is Agent Enabled (architecture): {cfg.is_agent_enabled('architecture')}")

    # Build input state for ArchitectureAgent as in a real scan
    # Check repo_detector output or repository_profile and repository_context
    profile = {
        "primary_language": "python",
        "detected_endpoints": ["/api/v1/agentic-scan", "/api/v1/scans", "/api/v1/business-intent"],
        "entry_points": ["backend/app/api/v1/agentic_scan.py", "backend/app/main.py"],
        "frameworks": ["FastAPI"],
        "total_files": 45
    }
    repo_ctx = {
        "auth_modules": ["Session/JWT Authentication Header"],
        "database_layers": ["ORM Data Access Layer"]
    }
    findings = [{"finding_id": "FIND-01", "severity": "High", "rule_id": "CWE-89", "category": "SQL Injection"}]

    state = create_initial_state(
        scan_id="audit_arch_scan_001",
        repository_profile=profile,
        repository_context=repo_ctx,
        findings=findings,
        scan_mode="full_scan"
    )

    agent = ArchitectureAgent()
    
    # Let's inspect the evidence block constructed by ArchitectureAgent
    endpoints = profile.get("detected_endpoints", [])
    entry_points = profile.get("entry_points", [])
    frameworks = profile.get("frameworks", [])

    service_boundaries = [f"service:{profile.get('primary_language', 'core')}"]
    auth_flows = repo_ctx.get("auth_modules", ["Session/JWT Authentication Header"])
    db_interactions = repo_ctx.get("database_layers", ["ORM Data Access Layer"])
    api_relationships = [f"API Endpoint: {ep}" for ep in endpoints[:5]]
    external_integrations = [f for f in frameworks if f in ["FastAPI", "Spring Boot", "NestJS", "Actix-web"]]

    trust_boundaries = []
    if endpoints or entry_points:
        trust_boundaries.append(
            "Public HTTP Gateway -> Application Controller "
            f"(evidenced by {len(endpoints)} detected endpoint(s) / "
            f"{len(entry_points)} entry point(s))"
        )
    if repo_ctx.get("database_layers"):
        trust_boundaries.append(
            "Application Layer -> Database "
            f"(evidenced by database layer(s): {', '.join(repo_ctx.get('database_layers', []))})"
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

    print("\n[ARCHITECTURE AGENT INPUT EVIDENCE BLOCK]")
    print(evidence_block)

    req = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id="audit_arch_scan_001",
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block=evidence_block,
        max_tokens=600,
        reasoning_effort="low",
    )

    service = ReasoningGateway(config=cfg)
    prompt, truncated = service._build_prompt(req)
    print("\n[CONSTRUCTED PROMPT SENT TO LLM]")
    print(prompt)

    print("\n[EXECUTING LIVE REASONING REQUEST]")
    ai_res = service.reason(req)
    
    print(f"\n[REASONING RESULT]")
    print(f"Available: {ai_res.available}")
    print(f"Error: '{ai_res.error}'")
    print(f"Latency: {ai_res.latency_ms} ms")
    print(f"Response Object Present: {ai_res.response is not None}")
    if ai_res.response:
        print(f"Raw Output:\n{ai_res.response.raw}")
        print(f"Problems Count: {len(ai_res.response.problems)}")
        if ai_res.response.problems:
            print(f"Problems: {ai_res.response.problems}")
        print(f"Parsed Findings Count: {len(ai_res.response.findings)}")
        for i, f in enumerate(ai_res.response.findings):
            print(f"  Finding [{i+1}]: {f.to_dict()}")

    # Process via ArchitectureAgent
    new_state = agent._process(state)
    insights_after_agent = new_state.get("ai_architecture_insights", [])
    print(f"\n[ai_architecture_insights IMMEDIATELY AFTER ArchitectureAgent]: {len(insights_after_agent)}")
    for item in insights_after_agent:
        print("  ", item)

    print(f"\n[grok_status]: {new_state.get('architecture_context', {}).get('grok_status')}")
    print(f"[agent_reason]: {new_state.get('architecture_context', {}).get('agent_reason')}")

if __name__ == "__main__":
    run_pipeline_audit()
