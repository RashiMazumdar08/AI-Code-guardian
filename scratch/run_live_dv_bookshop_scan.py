import sys
import os
import json
import logging
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))
logging.basicConfig(level=logging.INFO)

from guardian.intent.ingestion.document_loader import DocumentLoader
from guardian.intent.parser.rule_parser import RuleParser
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.agents.business.agent import BusinessAgent
from guardian.orchestrator.state import create_initial_state

def run_live_trace():
    pdf_path = Path("data/business_docs/DV_Bookshop_Business_Rules.pdf")
    loader = DocumentLoader(docs_dir=pdf_path.parent)
    reqs = loader.extract_actionable_requirements()
    
    parser = RuleParser()
    rules = parser.parse_all(reqs)
    
    matcher = RuleMatcher()
    # Evaluate against workspace profiles
    ws_profiles = RuleMatcher._profiles_from_workspace(Path.cwd())
    eval_results = matcher.evaluate_all(rules, findings=[])

    captured_requests = []
    
    from guardian.reasoning.gateway import ReasoningGateway
    orig_reason = ReasoningGateway.reason

    def mock_reason(self_gw, req):
        captured_requests.append(req)
        return orig_reason(self_gw, req)

    ReasoningGateway.reason = mock_reason

    state = create_initial_state(
        scan_id="scan-dv-bookshop-live-001",
        repository_profile={"repo_path": str(Path.cwd()), "frameworks": ["flask", "react"]}
    )
    state["business_intent_results"] = {
        "status": "SUCCESS",
        "total_rules": len(eval_results),
        "documents": ["DV_Bookshop_Business_Rules.pdf"],
        "findings": eval_results
    }
    state["business_context"] = {"domain": "e-commerce", "criticality": "HIGH"}

    agent = BusinessAgent()
    final_state = agent._process(state)

    ReasoningGateway.reason = orig_reason

    ai_insights_map = {
        insight.get("policy_id") or insight.get("rule_id"): insight
        for insight in final_state.get("ai_business_insights", [])
    }
    
    bi_res = final_state.get("business_intent_results", {})
    analyzed_policies = set(bi_res.get("analyzed_policies", []))
    skipped_policies = set(bi_res.get("skipped_policies", []))

    print("\n" + "="*80)
    print("DV-BOOKSHOP CANONICAL POLICY LIVE TRACE REPORT")
    print("="*80 + "\n")

    for f in eval_results:
        p_id = f.get("rule_id")
        det_verdict = f.get("status")
        score = f.get("score", 0.0)
        
        is_eligible = det_verdict in ("PARTIAL", "INSUFFICIENT_EVIDENCE", "INSUFFICIENT") or score < 0.8
        
        executed = p_id in analyzed_policies
        skipped = p_id in skipped_policies
        
        req_sent = next((r for r in captured_requests if f"[POLICY {p_id}]" in r.business_block), None)
        
        files_sent = "None"
        if req_sent:
            ev_block = req_sent.evidence_block
            if "No workspace implementation evidence found" in ev_block:
                files_sent = "None (No matching workspace evidence)"
            else:
                lines = [ln.strip() for ln in ev_block.splitlines() if ln.strip().startswith("[E")]
                files_sent = "; ".join(lines) if lines else ev_block[:150]

        ai_insight = ai_insights_map.get(p_id)
        if ai_insight:
            ai_verdict = ai_insight.get("verdict") or ai_insight.get("status")
            conf = f"{Math.round(ai_insight.get('confidence', 0.85)*100)}%" if 'Math' in globals() else f"{int(ai_insight.get('confidence', 0.85)*100)}%"
            reason = ai_insight.get("reason") or ai_insight.get("description")
        elif executed:
            ai_verdict = "EXECUTED (Zero Findings)"
            conf = "85%"
            reason = "Reasoning service returned clean verdict without vulnerability findings."
        elif skipped:
            ai_verdict = "SKIPPED (Token Budget Limit)"
            conf = "N/A"
            reason = "Skipped to preserve scan token budget for prior policies."
        else:
            ai_verdict = "N/A (Not Evaluated by AI)"
            conf = "N/A"
            reason = "Not eligible or not reached."

        print(f"Policy: {p_id} — {f.get('title')}")
        print(f"  deterministic verdict: {det_verdict} (Score: {score})")
        print(f"  AI eligible          : {is_eligible}")
        print(f"  AI executed/skipped  : {'EXECUTED' if executed else ('SKIPPED' if skipped else 'NOT_CALLED')}")
        print(f"  exact files/functions: {files_sent}")
        print(f"  AI verdict           : {ai_verdict}")
        print(f"  confidence           : {conf}")
        print(f"  reason               : {reason}")
        print("-" * 80)

if __name__ == "__main__":
    run_live_trace()
