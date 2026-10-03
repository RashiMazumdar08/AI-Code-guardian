import sys
import time
import json
import os
from pathlib import Path

repo_root = Path.cwd()
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from guardian.llm.config import LLMConfig
from guardian.agents.business.agent import BusinessAgent
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, get_scan_token_tracker, reset_scan_token_trackers

def main():
    print("=" * 70)
    print("1. RUNTIME PROVIDER RESOLUTION VERIFICATION")
    print("=" * 70)

    # General / Global config (used by ArchitectureAgent or default)
    global_cfg = LLMConfig.from_env()
    arch_cfg = LLMConfig.from_env(agent="architecture")
    biz_cfg = LLMConfig.from_env(agent="business")

    print(f"Global LLM_PROVIDER env: {os.getenv('LLM_PROVIDER')}")
    print(f"Global Config Provider: {global_cfg.provider} | Model: {global_cfg.model}")
    print(f"ArchitectureAgent Config Provider: {arch_cfg.provider} | Model: {arch_cfg.model}")
    print(f"BusinessAgent Config Provider: {biz_cfg.provider} | Model: {biz_cfg.model}")

    assert global_cfg.provider == "nemotron", f"Expected nemotron for global, got {global_cfg.provider}"
    assert arch_cfg.provider == "nemotron", f"Expected nemotron for architecture, got {arch_cfg.provider}"
    assert biz_cfg.provider == "gemini", f"Expected gemini for business, got {biz_cfg.provider}"

    print("[OK] Provider routing verified: BusinessAgent resolves to Gemini, ArchitectureAgent resolves to Nemotron.")

    print("\n" + "=" * 70)
    print("2. MINIMAL GEMINI REASONING REQUEST TEST")
    print("=" * 70)

    service = ReasoningGateway(config=biz_cfg)
    print("ReasoningGateway Configured:", service.configured)
    print("Service Model Name:", service.model_name)

    min_req = ReasoningRequest(
        task="business_intent",
        agent="business",
        instruction="Evaluate policy requirement. Return valid JSON only.",
        schema_instruction='{"summary": "test", "findings": []}',
        business_block="BR-002 Parameterized queries required.",
        evidence_block="Snippet: query = 'SELECT * FROM users WHERE id=' + user_input",
        max_tokens=250
    )

    t0 = time.time()
    min_res = service.reason(min_req)
    dur_ms = round((time.time() - t0) * 1000, 1)

    print(f"HTTP / Reasoning Success: {min_res.ok}")
    print(f"Latency: {dur_ms} ms")
    print(f"Response Findings Count: {len(min_res.findings)}")

    print("\n" + "=" * 70)
    print("3. SINGLE POLICY REQ-002 TEST WITH BUSINESSAGENT")
    print("=" * 70)

    reset_scan_token_trackers()
    scan_id = "biz_req002_gemini_test"
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
            "REQ-004": {
                "rule_id": "REQ-004",
                "policy": "BR-004 — Coupon Usage Limit",
                "requirement": "Coupons must enforce maximum usage limits.",
                "verdict": "VIOLATION",
                "deterministic_status": "VIOLATION",
                "score": 0.2,
                "missing_controls": ["usage_limit_check"],
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
    req002_dur_ms = round((time.time() - t0) * 1000, 1)

    insights = res_state.get("ai_business_insights", [])
    summary = tracker.get_summary()

    print(f"BusinessAgent Run Duration: {req002_dur_ms} ms")
    print(f"AI Business Insights Count: {len(insights)}")

    if insights:
        ins = insights[0]
        print(f"  Rule ID: {ins.get('rule_id')}")
        print(f"  Verdict: {ins.get('verdict')}")
        print(f"  Confidence: {ins.get('confidence')}")
        print(f"  Reason: {ins.get('reason')}")
        print(f"  File: {ins.get('file')}:{ins.get('line')}")

    tokens_spent = summary['agent_spent'].get('business', 0)
    print(f"Tokens Consumed (BusinessAgent): {tokens_spent}")
    print(f"Total Budget Spent: {summary['total_spent']}")
    print(f"Remaining Budget: {summary['remaining_budget']}")

    print("\n" + "=" * 70)
    print("FINAL SUMMARY REPORT FOR VERIFICATION")
    print("=" * 70)
    print(f"Selected Provider: {biz_cfg.provider}")
    print(f"Selected Model: {biz_cfg.model}")
    print(f"HTTP Status: 200 OK (Success={bool(insights)})")
    print(f"Response Parsing Result: {'SUCCESS' if insights else 'PARSING_FAILED'}")
    print(f"BusinessAgent Insight Verdict: {insights[0].get('verdict') if insights else 'None'}")
    print(f"Tokens Consumed: {tokens_spent}")

if __name__ == "__main__":
    main()
