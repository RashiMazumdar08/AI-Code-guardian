import sys
import os
import json

cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state

def test_full_pipeline_tracing():
    print("=" * 70)
    print("TRACING COMPLETE ARCHITECTURE PIPELINE WITH ACTUAL REPO PROFILE")
    print("=" * 70)

    # 1. Adopt or build realistic repository profile and context for DV Bookshop or current project
    from guardian.intent.matcher.rule_matcher import RuleMatcher
    ws_p = RuleMatcher._profiles_from_workspace()
    
    print(f"Total RuleMatcher profiles: {len(ws_p)}")
    controls_profiles = [wp for wp in ws_p if wp.controls]
    print(f"Profiles with controls: {len(controls_profiles)}")
    for wp in controls_profiles[:10]:
        print(f"  file={wp.file} | fn={wp.function_name} | controls={wp.controls[:2]}")

    cfg = LLMConfig.from_env()
    service = ReasoningGateway(config=cfg)

    # Test 5 reasoning calls with the exact same evidence to check LLM stochasticity / conclusion
    arch_ev_items = [
        "[E1] Service boundaries: ['service:python']",
        "[E2] Auth flows: ['Session/JWT Authentication Header']",
        "[E3] DB interactions: ['ORM Data Access Layer']",
        "[E4] Trust boundaries: ['Public HTTP Gateway -> Application Controller (evidenced by 40 detected endpoint(s) / 18 entry point(s))', 'Application Layer -> Database (evidenced by database layer(s): ORM Data Access Layer)']",
        "[E5] API Endpoints: ['API Endpoint: /api/v1/agentic-scan', 'API Endpoint: /api/v1/scans', 'API Endpoint: /api/v1/business-intent', 'API Endpoint: /api/v1/reports', 'API Endpoint: /api/v1/findings']",
    ]
    for p_idx, wp in enumerate(controls_profiles[:5]):
        arch_ev_items.append(
            f"[E{len(arch_ev_items)+1}] Component: {wp.file} | Function: {wp.function_name} | Controls: {','.join(wp.controls[:2])}"
        )

    evidence_block = "\n".join(arch_ev_items)

    req = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id="audit_arch_scan_002",
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block=evidence_block,
        max_tokens=600,
        reasoning_effort="low",
    )

    print("\n--- EVIDENCE BLOCK SENT ---")
    print(evidence_block)

    print("\n--- RUNNING 3 REASONING CALLS TO TEST MODEL CONCLUSION STABILITY ---")
    for attempt in range(1, 4):
        # Disable gateway internal cache for testing variance
        service._enable_cache = False
        res = service.reason(req)
        print(f"\nAttempt #{attempt}:")
        print(f"  Latency: {res.latency_ms} ms")
        if res.response:
            print(f"  Summary: {res.response.summary}")
            print(f"  Findings count: {len(res.response.findings)}")
            for f in res.response.findings:
                print(f"    - Title: {f.title}")
                print(f"      Severity: {f.severity}")
                print(f"      Reason: {f.reason}")
                print(f"      File: {f.file}:{f.line}")
        else:
            print(f"  Error: {res.error}")

if __name__ == "__main__":
    test_full_pipeline_tracing()
