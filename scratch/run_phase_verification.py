import sys
import time
import json
import os
from pathlib import Path

repo_root = Path.cwd()
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from guardian.agents.business.agent import BusinessAgent
from guardian.reasoning.gateway import get_scan_token_tracker, reset_scan_token_trackers
from guardian.llm.config import LLMConfig

def run_phase1():
    print("=" * 70)
    print("PHASE 1 — ONE POLICY ONLY (REQ-002) WITH NEMOTRON")
    print("=" * 70)
    
    cfg = LLMConfig.from_env()
    print("Provider:", cfg.provider)
    print("Model:", cfg.model)
    print("Timeout:", cfg.timeout)

    reset_scan_token_trackers()
    scan_id = "phase1_test_req002"
    tracker = get_scan_token_tracker(scan_id)

    agent = BusinessAgent()
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
    dur_ms = round((time.time() - t0) * 1000, 1)

    insights = res_state.get("ai_business_insights", [])
    summary = tracker.get_summary()

    print(f"\nPhase 1 Execution Time: {dur_ms} ms ({round(dur_ms/1000, 2)} s)")
    print(f"AI Business Insights Count: {len(insights)}")

    if insights:
        ins = insights[0]
        print(f"  Rule ID: {ins.get('rule_id')}")
        print(f"  Verdict: {ins.get('verdict')}")
        print(f"  Reason: {ins.get('reason')}")
        print(f"  Confidence: {ins.get('confidence')}")

    print(f"Tokens Spent (BusinessAgent): {summary['agent_spent'].get('business', 0)}")
    print(f"Total Spent: {summary['total_spent']}")
    print(f"Remaining Budget: {summary['remaining_budget']}")

    passed = len(insights) == 1 and ins.get('verdict') in ["COMPLIANT", "VIOLATION", "PARTIAL", "INSUFFICIENT_EVIDENCE"]
    print(f"\nPHASE 1 RESULT: {'PASS' if passed else 'FAIL'}")
    return passed, {
        "latency_ms": dur_ms,
        "verdict": insights[0].get("verdict") if insights else None,
        "tokens": summary['agent_spent'].get('business', 0),
        "insights_count": len(insights)
    }

def run_phase2():
    print("\n" + "=" * 70)
    print("PHASE 2 — THREE POLICIES (REQ-002, REQ-001, REQ-003) WITH NEMOTRON")
    print("=" * 70)

    cfg = LLMConfig.from_env()
    print("Provider:", cfg.provider)
    print("Model:", cfg.model)

    reset_scan_token_trackers()
    scan_id = "phase2_test_3policies"
    tracker = get_scan_token_tracker(scan_id)

    agent = BusinessAgent()
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
    dur_ms = round((time.time() - t0) * 1000, 1)

    insights = res_state.get("ai_business_insights", [])
    summary = tracker.get_summary()

    print(f"\nPhase 2 Total Execution Time: {dur_ms} ms ({round(dur_ms/1000, 2)} s)")
    print(f"AI Business Insights Count: {len(insights)}")

    for i, ins in enumerate(insights):
        print(f"  [{i+1}] Policy: {ins.get('rule_id')} | Verdict: {ins.get('verdict')} | Reason: {ins.get('reason')}")

    tokens_used = summary['agent_spent'].get('business', 0)
    print(f"Tokens Spent (BusinessAgent): {tokens_used}")

    passed = len(insights) == 3
    print(f"\nPHASE 2 RESULT: {'PASS' if passed else 'FAIL'}")
    return passed, {
        "latency_ms": dur_ms,
        "insights_count": len(insights),
        "tokens": tokens_used,
        "insights": insights
    }

if __name__ == "__main__":
    p1_pass, p1_data = run_phase1()
    if p1_pass:
        p2_pass, p2_data = run_phase2()
    else:
        print("\nPhase 1 failed. Skipping Phase 2.")
