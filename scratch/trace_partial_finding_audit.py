"""
Trace Audit Script for Low Confidence / Partial / Insufficient Business Intent Findings
"""
import json
import os
from pathlib import Path

from guardian.intent.parser.rule_parser import ParsedRule
from guardian.intent.matcher.rule_matcher import RuleMatcher, BehaviorProfile
from guardian.agents.business.agent import BusinessAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, ReasoningResult
from guardian.reasoning.schemas import parse_business_intent_response
from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result


def audit_partial_finding_pipeline():
    print("==================================================")
    print("TRACE AUDIT: DETERMINISTIC PARTIAL/INSUFFICIENT FINDINGS -> BUSINESS AGENT")
    print("==================================================\n")

    # 1. Construct deterministic findings with PARTIAL verdict and score ~0.28 (28%)
    det_findings = [
        {
            "rule": "Every privileged state mutation or account transfer must record an immutable audit trail entry.",
            "rule_id": "REQ-008",
            "title": "Audit Trail Requirement",
            "status": "PARTIAL",
            "what": "Control 'audit trail' detected but target action requires review",
            "why": "Partial policy alignment",
            "how": "Verify binding between audit trail and action handler",
            "evidence": "file: services/audit_service.py · function: record_audit_event",
            "score": 0.28,
            "source_file": "services/audit_service.py",
            "line_number": 42,
            "actions": ["record_audit_event"],
            "controls": ["generic_control"],
            "matched_action": "account_transfer",
            "matched_condition": "none",
            "matched_control": "generic_control"
        },
        {
            "rule": "High-value refund operations exceeding 50,000 USD require explicit manager approval.",
            "rule_id": "REQ-001",
            "title": "Manager Approval Requirement",
            "status": "INSUFFICIENT_EVIDENCE",
            "what": "No relevant action or control logic found in code AST",
            "why": "Codebase contains no matching domain execution paths",
            "how": "Upload related source code or annotate function implementations",
            "evidence": "file: N/A · function: N/A",
            "score": 0.0,
            "source_file": "services/payment_service.py",
            "line_number": 15,
            "actions": [],
            "controls": [],
            "matched_action": "refund",
            "matched_condition": "> 50000",
            "matched_control": "manager approval"
        }
    ]

    intent_result = {
        "status": "SUCCESS",
        "alignment_score": 0.28,
        "alignment_percentage": 28.0,
        "total_rules": 2,
        "matched": 0,
        "violated": 0,
        "partial": 1,
        "insufficient": 1,
        "documents": ["business_rules.pdf"],
        "findings": det_findings
    }

    # 2. Inspect what BusinessAgent constructs from intent_result
    captured_requests = []
    os.environ["LLM_ENABLED"] = "true"
    os.environ["LLM_AGENT_BUSINESS_ENABLED"] = "true"
    os.environ["XAI_API_KEY"] = "test_xai_key_mock"

    class AuditReasoningGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req: ReasoningRequest) -> ReasoningResult:
            captured_requests.append(req)
            # Return a valid mock Grok response resolving the PARTIAL requirement
            fake_grok_json = json.dumps({
                "summary": "AI Business Agent evaluated partial/insufficient policy rules against AST evidence.",
                "findings": [
                    {
                        "evidence_ids": ["E1"],
                        "category": "business_intent",
                        "severity": "Medium",
                        "confidence": 0.88,
                        "verdict": "PARTIAL",
                        "reason": "record_audit_event logs general events, but does not explicitly bind to privileged account_transfer actions.",
                        "recommendation": "Bind audit logging explicitly inside account transfer handler.",
                        "file": "services/audit_service.py",
                        "line": 42,
                        "function": "record_audit_event",
                        "policy_id": "REQ-008",
                        "requirement": "Every privileged state mutation or account transfer must record an immutable audit trail entry."
                    },
                    {
                        "evidence_ids": ["E2"],
                        "category": "business_intent",
                        "severity": "High",
                        "confidence": 0.92,
                        "verdict": "VIOLATION",
                        "reason": "process_refund in payment_service.py performs refunds without manager authorization checks.",
                        "recommendation": "Add manager approval check prior to executing refunds exceeding $50,000.",
                        "file": "services/payment_service.py",
                        "line": 15,
                        "function": "process_refund",
                        "policy_id": "REQ-001",
                        "requirement": "High-value refund operations exceeding 50,000 USD require explicit manager approval."
                    }
                ]
            })
            parsed = parse_business_intent_response(fake_grok_json, model="grok-beta")
            return ReasoningResult(response=parsed, available=True)

    import guardian.reasoning.gateway as reasoning_gw_module
    reasoning_gw_module.ReasoningGateway = AuditReasoningGateway

    state = create_initial_state(
        scan_id="scan-audit-partial",
        repository_profile={"repo_path": str(Path.cwd()), "frameworks": ["python"]}
    )
    state["business_intent_results"] = intent_result

    agent = BusinessAgent()
    new_state = agent.run(state)

    print("--- 1. DETERMINISTIC FINDINGS PASSED IN ---")
    for f in det_findings:
        print(f"Rule ID: {f['rule_id']} | Status: {f['status']} | Score: {f['score']} | What: {f['what']}")

    print("\n--- 2. BUSINESS AGENT PROMPT ANALYSIS ---")
    if captured_requests:
        req = captured_requests[-1]
        print(f"Instruction:\n{req.instruction}\n")
        print(f"Business Block:\n{req.business_block}\n")
        print(f"Evidence Block:\n{req.evidence_block}\n")

    print("--- 3. AI FINDINGS / INSIGHTS PRODUCED ---")
    ai_insights = new_state.get("ai_business_insights", [])
    print(f"ai_business_insights count: {len(ai_insights)}")
    for idx, ins in enumerate(ai_insights):
        print(f"[{idx+1}] Policy: {ins.get('extras', {}).get('policy_id') or ins.get('policy_id')} | Verdict: {ins.get('extras', {}).get('verdict') or ins.get('verdict')} | Reason: {ins.get('reason')}")

    print("\n--- 4. DETERMINISTIC VIOLATIONS LIST AFTER AGENT RUN ---")
    violations = new_state.get("business_violations", [])
    print(f"business_violations count: {len(violations)}")
    for idx, v in enumerate(violations):
        print(f"[{idx+1}] Rule: {v.get('rule_id')} | Status: {v.get('status')} | What: {v.get('what')} | Source: {v.get('source', 'STATIC')}")

    print("\n--- 5. API ENVELOPE DUMP ---")
    curated = {
        "completed_agents": ["business"],
        "business_violations": new_state.get("business_violations", []),
        "business_intent_results": new_state.get("business_intent_results", {}),
        "ai_business_insights": new_state.get("ai_business_insights", [])
    }
    api_result = _build_agentic_analysis_result("agentic-audit-partial", {"source_scan_id": "base-partial"}, curated)
    api_insights = api_result.get("business_analysis", {}).get("ai_business_insights")
    print(f"API result.business_analysis.ai_business_insights count: {len(api_insights or [])}")


if __name__ == "__main__":
    audit_partial_finding_pipeline()
