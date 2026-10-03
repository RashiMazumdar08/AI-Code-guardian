import sys
import time
import json
import os
from pathlib import Path

repo_root = Path.cwd()
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from guardian.agents.business.agent import BusinessAgent
from guardian.reasoning.gateway import NemotronReasoningService, reset_scan_token_trackers, get_scan_token_tracker
from guardian.llm.config import LLMConfig

def main():
    print("=== FOCUSED BUSINESSAGENT REASONING TEST (NEMOTRON PROVIDER) ===")
    cfg = LLMConfig.from_env()

    print("Provider:", cfg.provider)
    print("Model:", cfg.model)

    reset_scan_token_trackers()
    scan_id = "focused_biz_test_001"
    tracker = get_scan_token_tracker(scan_id)

    agent = BusinessAgent()

    # Construct state with unresolved policies REQ-002, REQ-001, REQ-003
    state = {
        "scan_id": scan_id,
        "scan_mode": "full_scan",
        "business_intent_results": {
            "REQ-002": {
                "rule_id": "REQ-002",
                "policy": "BR-002 — Parameterized SQL Queries",
                "requirement": "All database queries must use parameterized statements.",
                "verdict": "INSUFFICIENT_EVIDENCE",
                "deterministic_status": "INSUFFICIENT_EVIDENCE",
                "score": 0.0,
                "missing_controls": ["parameterized_query"],
                "matched_file": "app.py",
                "matched_function": "login",
                "matched_line": 677,
                "matched_snippet": "c.execute('SELECT * FROM users WHERE username = ' + input)",
            },
            "REQ-001": {
                "rule_id": "REQ-001",
                "policy": "BR-001 — Session Timeout",
                "requirement": "Session timeout must be configured to expire after inactivity.",
                "verdict": "PARTIAL",
                "deterministic_status": "PARTIAL",
                "score": 0.5,
                "missing_controls": ["inactivity_timeout"],
                "matched_file": "app.py",
                "matched_function": "init",
                "matched_line": 20,
                "matched_snippet": "session.permanent = True",
            },
            "REQ-003": {
                "rule_id": "REQ-003",
                "policy": "BR-003 — Authoritative Price Calculation",
                "requirement": "Server price must be calculated authoritatively before payment.",
                "verdict": "PARTIAL",
                "deterministic_status": "PARTIAL",
                "score": 0.5,
                "missing_controls": ["server_price_check"],
                "matched_file": "app.py",
                "matched_function": "checkout",
                "matched_line": 150,
                "matched_snippet": "total = request.json.get('total')",
            },
            "REQ-004": {
                "rule_id": "REQ-004",
                "policy": "BR-004 — Coupon Usage Limit",
                "requirement": "Coupons must enforce maximum usage limits.",
                "verdict": "VIOLATION",
                "deterministic_status": "VIOLATION",
                "score": 0.2,
                "missing_controls": ["usage_limit_check"],
            },
            "REQ-005": {
                "rule_id": "REQ-005",
                "policy": "BR-005 — Balance Verification",
                "requirement": "Balance check must use authoritative total.",
                "verdict": "VIOLATION",
                "deterministic_status": "VIOLATION",
                "score": 0.3,
                "missing_controls": ["balance_check"],
            }
        },
        "business_context": {
            "domain": "Retail / E-commerce",
            "criticality": "HIGH",
        },
        "ai_business_insights": [],
        "completed_agents": [],
    }

    t0 = time.time()
    res_state = agent.run(state)
    dur = round((time.time() - t0) * 1000, 1)

    print(f"\nBusinessAgent run finished in {dur}ms")
    insights = res_state.get("ai_business_insights", [])
    print(f"AI Business Insights Count: {len(insights)}")

    for i, ins in enumerate(insights):
        print(f"\n--- AI Insight {i+1} ---")
        print("  Rule ID:", ins.get("rule_id"))
        print("  Verdict:", ins.get("verdict"))
        print("  Confidence:", ins.get("confidence"))
        print("  Reason:", ins.get("reason"))
        print("  File:", ins.get("file"))
        print("  Line:", ins.get("line"))

    summary = tracker.get_summary()
    print("\n" + "=" * 70)
    print("TOKEN BUDGET & ADMISSION AUDIT")
    print("=" * 70)
    print(f"TOTAL BUDGET = 6500")
    print(f"TOTAL ACTUAL EXTERNAL LLM TOKENS = {summary['total_spent']}")
    print(f"TOTAL UNUSED = {summary['remaining_budget']}")
    print(f"BUSINESS SPENT = {summary['agent_spent'].get('business', 0)}")
    print("=" * 70)

if __name__ == "__main__":
    main()
