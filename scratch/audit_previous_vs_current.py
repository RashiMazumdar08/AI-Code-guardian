import sys
import os
import json

cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, reset_scan_token_trackers
from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state

def run_trace_both_scenarios():
    print("=" * 75)
    print("COMPARING ARCHITECTURE AGENT EXECUTION SCENARIOS")
    print("=" * 75)

    cfg = LLMConfig.from_env()

    # Scenario A: ArchitectureAgent run with 6 evidence items (within 1100 token cap)
    print("\n--- SCENARIO A: 6 Evidence Items (Admitted: ~1060 tokens <= 1100 cap) ---")
    reset_scan_token_trackers()
    service_a = ReasoningGateway(config=cfg)
    service_a._enable_cache = False

    ev_a = [
        "[E1] Service boundaries: ['service:python']",
        "[E2] Auth flows: ['Session/JWT Authentication Header']",
        "[E3] DB interactions: ['ORM Data Access Layer']",
        "[E4] Trust boundaries: ['Public HTTP Gateway -> Application Controller (evidenced by 40 detected endpoint(s) / 18 entry point(s))', 'Application Layer -> Database (evidenced by database layer(s): ORM Data Access Layer)']",
        "[E5] API Endpoints: ['API Endpoint: /api/v1/agentic-scan', 'API Endpoint: /api/v1/scans', 'API Endpoint: /api/v1/business-intent', 'API Endpoint: /api/v1/reports', 'API Endpoint: /api/v1/findings']",
        "[E6] Component: backend\\app\\api\\v1\\agentic_scan.py | Function: _curated_state | Controls: validation"
    ]
    req_a = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id="scen_a_1",
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block="\n".join(ev_a),
        max_tokens=600,
        reasoning_effort="low",
    )
    res_a = service_a.reason(req_a)
    print(f"Admitted/Available: {res_a.available}")
    if res_a.available and res_a.response:
        print(f"Summary: {res_a.response.summary}")
        print(f"Findings Count: {len(res_a.response.findings)}")
        for f in res_a.response.findings:
            print(f"  Finding: {json.dumps(f.to_dict(), ensure_ascii=True, indent=2)}")

    # Scenario B: What if evidence explicitly mentions unauthenticated exposure or missing auth filter on Public HTTP Gateway?
    print("\n--- SCENARIO B: Evidence including missing auth / direct public HTTP gateway exposure ---")
    reset_scan_token_trackers()
    service_b = ReasoningGateway(config=cfg)
    service_b._enable_cache = False

    ev_b = [
        "[E1] Service boundaries: ['service:python']",
        "[E2] Auth flows: ['No global auth middleware detected on entry points']",
        "[E3] DB interactions: ['ORM Data Access Layer']",
        "[E4] Trust boundaries: ['Public HTTP Gateway -> Application Controller (evidenced by 40 detected endpoint(s) / 18 entry point(s)) -- UNPROTECTED ROUTE EXPOSURE']",
        "[E5] API Endpoints: ['API Endpoint: /api/v1/agentic-scan', 'API Endpoint: /api/v1/scans', 'API Endpoint: /api/v1/business-intent']",
        "[E6] Component: backend\\app\\api\\v1\\agentic_scan.py | Function: _curated_state | Controls: none"
    ]
    req_b = ReasoningRequest(
        task="architecture_reasoning",
        agent="architecture",
        scan_id="scen_b_1",
        instruction=(
            "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
            "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
        ),
        evidence_block="\n".join(ev_b),
        max_tokens=600,
        reasoning_effort="low",
    )
    res_b = service_b.reason(req_b)
    print(f"Admitted/Available: {res_b.available}")
    if res_b.available and res_b.response:
        print(f"Summary: {res_b.response.summary}")
        print(f"Findings Count: {len(res_b.response.findings)}")
        for f in res_b.response.findings:
            print(f"  Finding: {json.dumps(f.to_dict(), ensure_ascii=True, indent=2)}")

if __name__ == "__main__":
    run_trace_both_scenarios()
