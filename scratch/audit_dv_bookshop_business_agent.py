"""
Audit script for Business Agent scan trace on DV-Bookshop & Business Documents
"""
import json
import os
from pathlib import Path

from guardian.intent.engine import BusinessIntentEngine
from guardian.agents.business.agent import BusinessAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result


def audit_business_scan():
    print("==================================================")
    print("STARTING AUDIT OF BUSINESS INTENT & BUSINESS AGENT")
    print("==================================================\n")

    # Check available documents in data/business_docs
    engine = BusinessIntentEngine()
    docs = engine.loader.list_documents()
    print(f"1. Documents discovered in business docs dir: {[d['filename'] for d in docs]}")

    # Run deterministic engine
    intent_result = engine.run(scan_findings=[])
    print(f"\n2. Deterministic Engine Output Status: {intent_result.get('status')}")
    print(f"Total rules evaluated: {intent_result.get('total_rules')}")
    print(f"Alignment Score: {intent_result.get('alignment_score')}%")

    findings = intent_result.get("findings", [])
    print(f"\n3. Deterministic Findings Count: {len(findings)}")

    for idx, f in enumerate(findings):
        print(f"\n--- Finding [{idx+1}] ---")
        print(f"Rule/Policy ID: {f.get('rule_id')}")
        print(f"Title / Rule: {f.get('title') or f.get('rule')}")
        print(f"Verdict/Status: {f.get('status')}")
        print(f"Confidence/Score: {f.get('score')}")
        print(f"What: {f.get('what')}")
        print(f"Why: {f.get('why')}")
        print(f"How: {f.get('how')}")
        print(f"Evidence: {f.get('evidence')}")
        print(f"Source File/Line: {f.get('source_file') or f.get('file')}:{f.get('line_number')}")

    # Trace BusinessAgent execution
    # Capture the exact prompt sent to ReasoningGateway
    captured_requests = []
    original_reason = ReasoningGateway.reason

    def logging_reason(self, req: ReasoningRequest):
        captured_requests.append(req)
        return original_reason(self, req)

    ReasoningGateway.reason = logging_reason

    # Run BusinessAgent with workspace profile pointing to current workspace
    workspace_path = str(Path.cwd())
    state = create_initial_state(
        scan_id="scan-audit-bus",
        repository_profile={"repo_path": workspace_path, "frameworks": ["python", "flask"]}
    )

    agent = BusinessAgent()
    new_state = agent.run(state)

    bus_res = new_state.get("business_intent_results", {})
    grok_status = bus_res.get("grok_status")
    agent_reason = bus_res.get("agent_reason")

    print(f"\n4. BusinessAgent Grok Status: {grok_status}")
    print(f"BusinessAgent Reason: {agent_reason}")

    print(f"\n5. ReasoningGateway Requests Captured: {len(captured_requests)}")
    for idx, req in enumerate(captured_requests):
        print(f"\n--- Reasoning Request [{idx+1}] ---")
        print(f"Task: {req.task}")
        print(f"Instruction:\n{req.instruction}")
        print(f"Business Block:\n{req.business_block}")
        print(f"Evidence Block:\n{req.evidence_block}")

    ai_insights = new_state.get("ai_business_insights", [])
    print(f"\n6. State ai_business_insights Count: {len(ai_insights)}")
    for idx, ins in enumerate(ai_insights):
        print(f"  Insight [{idx+1}]: {json.dumps(ins, default=str)}")

    # API result envelope check
    curated = {
        "completed_agents": ["business"],
        "business_violations": new_state.get("business_violations", []),
        "business_intent_results": bus_res,
        "ai_business_insights": ai_insights
    }
    api_result = _build_agentic_analysis_result("agentic-audit-bus", {"source_scan_id": "base-audit"}, curated)
    api_insights = api_result.get("business_analysis", {}).get("ai_business_insights")
    print(f"\n7. API result.business_analysis.ai_business_insights Count: {len(api_insights or [])}")

if __name__ == "__main__":
    audit_business_scan()
