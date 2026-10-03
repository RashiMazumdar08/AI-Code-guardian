import json
import logging
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath("."))

# Enable info logging to see [BUSINESS BUDGET TRACE] and [TELEMETRY]
logging.basicConfig(level=logging.INFO, stream=sys.stdout)

from guardian.core.pipeline import ScanPipeline
from backend.app.api.v1.agentic_scan import _adopt_deterministic_report, _build_agentic_analysis_result
from guardian.orchestrator.state import create_initial_state
from guardian.orchestrator.workflow import OrchestratorWorkflow

def trace_real_scan():
    repo_path = Path("c:/Users/Rashi Mazumdar/Downloads/ai_features-main (2)/ai_features-main")
    
    print("=== Step 1: Running deterministic pipeline scan ===")
    pipeline = ScanPipeline()
    report_dict = pipeline.scan(repo_path)
    
    print("\n=== Step 2: Adopting report into agentic state ===")
    adopted = _adopt_deterministic_report(report_dict)
    
    initial_state = create_initial_state(
        scan_id="scan-live-trace-001",
        repository_profile=adopted["repository_profile"],
        scan_mode="full_scan",
        findings=adopted["findings"],
        evidence=adopted["evidence"]
    )
    
    # Inject deterministic business intent results with PARTIAL/INSUFFICIENT findings (like real DV-Bookshop scan)
    initial_state["business_intent_results"] = {
        "status": "SUCCESS",
        "total_rules": 2,
        "documents": ["policy.md"],
        "findings": [
            {
                "rule_id": "REQ-008",
                "rule": "Control 'generic_control' detected but target action requires review",
                "status": "PARTIAL",
                "score": 0.28,
                "matched_action": "profile",
                "matched_condition": "none",
                "matched_control": "generic_control",
                "what": "Partial policy alignment",
                "source_file": "app.py"
            },
            {
                "rule_id": "REQ-001",
                "rule": "Order processing audit log required",
                "status": "INSUFFICIENT_EVIDENCE",
                "score": 0.15,
                "matched_action": "process_order",
                "matched_condition": "none",
                "matched_control": "audit_log",
                "what": "Unverified audit control",
                "source_file": "app.py"
            }
        ]
    }
    
    print(f"Initial state scan_id: {initial_state.get('scan_id')}")
    print(f"Deterministic findings count: {len(adopted['findings'])}")
    
    print("\n=== Step 3: Running BusinessAgent directly with Gateway Interception ===")
    from guardian.reasoning.gateway import ReasoningGateway
    orig_reason = ReasoningGateway.reason
    captured_reqs = []
    def intercept_reason(self, req):
        captured_reqs.append(req)
        return orig_reason(self, req)
    monkeypatch_gateway = intercept_reason
    ReasoningGateway.reason = intercept_reason

    from guardian.agents.business.agent import BusinessAgent
    agent = BusinessAgent()
    final_state = agent._process(initial_state)
    ReasoningGateway.reason = orig_reason

    print("\n=== Step 4: Building AgenticAnalysisResult API response ===")
    record = {
        "source_scan_id": "det-scan-001",
        "status": "completed",
        "scan_mode": "full_scan",
        "started_at": 1000.0,
        "repository_profile": adopted["repository_profile"]
    }
    
    curated = {
        "scan_id": final_state.get("scan_id"),
        "scan_mode": final_state.get("scan_mode"),
        "active_agent": final_state.get("active_agent"),
        "completed_agents": final_state.get("completed_agents"),
        "business_context": final_state.get("business_context"),
        "business_intent_results": final_state.get("business_intent_results"),
        "business_violations": final_state.get("business_violations"),
        "ai_business_insights": final_state.get("ai_business_insights"),
    }
    
    api_result = _build_agentic_analysis_result("scan-live-trace-001", record, curated)
    
    bus_analysis = api_result.get("business_analysis", {})
    bus_results = bus_analysis.get("results", {})
    ai_insights = api_result.get("ai_business_insights", [])
    
    print("\n=== Step 5: Final API Field Inspection ===")
    if captured_reqs:
        req0 = captured_reqs[0]
        print(f"A. REQ-008 original requirement sent to Gemini: {req0.business_block}")
        print(f"C. files/snippets sent as implementation evidence:\n{req0.evidence_block}")
    
    det_f0 = initial_state.get("business_intent_results", {}).get("findings", [])[0]
    print(f"B. deterministic verdict/score: verdict={det_f0.get('status')}, score={det_f0.get('score')}")
    print(f"E. ai_business_insights count: {len(final_state.get('ai_business_insights', []) or [])}")
    print(f"F. final API business_analysis.ai_business_insights: count={len(bus_analysis.get('ai_business_insights', []))}")
    if ai_insights:
        print(f"   AI Insight details: {json.dumps(ai_insights, indent=2)}")
    print(f"G. whether the frontend renders the AI insight: {'Yes (renders insight card)' if ai_insights else 'No (shows status banner/subtext)'}")

if __name__ == "__main__":
    trace_real_scan()

    trace_real_scan()

