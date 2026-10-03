"""
Gemini Provider Connectivity & Reasoning Audit Test
===================================================
Tests Gemini provider selection, connectivity via OpenAI-compatible endpoint,
and BusinessAgent end-to-end reasoning without exposing API keys.
"""
import os
import sys
import logging

# Ensure guardian package is on sys.path
sys.path.insert(0, os.path.abspath("."))

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gemini_test")

def main():
    print("=" * 60)
    print("AUDITING LLM CONFIGURATION & GEMINI CONNECTIVITY")
    print("=" * 60)

    from guardian.llm.config import LLMConfig
    from guardian.llm.factory import create_llm, available_providers
    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
    from guardian.agents.business.agent import BusinessAgent

    cfg = LLMConfig.from_env()
    
    print("\n[LLM PROVIDER]")
    print(f"provider={cfg.provider}")
    print(f"model={cfg.model}")
    print(f"base_url={cfg.base_url}")
    print(f"available_providers={available_providers()}")
    print(f"configured={cfg.is_configured}")

    assert cfg.provider == "gemini", f"Expected provider 'gemini', got '{cfg.provider}'"
    print("\n[OK] Provider correctly resolved as 'gemini'")

    # Instantiate LLM via factory
    print("\n[LLM FACTORY TEST]")
    client = create_llm(config=cfg)
    print(f"Created LLM client instance: {type(client).__name__}")
    print(f"Model name: {client.model_name}")

    # Test direct completion via LLM client
    print("\n[GEMINI CONNECTIVITY TEST]")
    try:
        res = client.chat([
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with 'GEMINI_ONLINE'"}
        ], max_tokens=100)
        print("[OK] Gemini completion succeeded!")
        print(f"Latency: {res.latency_ms}ms")
        print(f"Content preview: {res.content.strip()[:50]}")
        conn_success = True
        conn_error = None
    except Exception as exc:
        clean_err = str(exc).encode("ascii", "ignore").decode("ascii")
        print(f"[FAIL] Gemini completion failed: {type(exc).__name__}: {clean_err}")
        conn_success = False
        conn_error = clean_err

    # Test ReasoningGateway structured output parsing
    print("\n[REASONING GATEWAY TEST]")
    service = ReasoningGateway(config=cfg)
    req = ReasoningRequest(
        task="business_intent",
        instruction="Evaluate business rule compliance for user cancellation.",
        evidence_block="[E1] Requirement: Customers may cancel an order only before the order is shipped.\n[E2] Code: def cancel_order(order_id): order.status = 'CANCELLED'",
        max_tokens=300
    )
    gw_res = service.reason(req)
    print(f"Reasoning available: {gw_res.available}")
    if gw_res.ok:
        print("[OK] ReasoningGateway call SUCCEEDED!")
        print(f"Findings count: {len(gw_res.findings)}")
        if gw_res.findings:
            print(f"Sample finding: {gw_res.findings[0].to_dict()}")
    else:
        clean_gw_err = gw_res.error.encode("ascii", "ignore").decode("ascii")
        print(f"Reasoning error / notice: {clean_gw_err}")

    # Test BusinessAgent end-to-end
    print("\n[BUSINESS AGENT END-TO-END TEST]")
    agent = BusinessAgent()
    sample_state = {
        "scan_id": "test-gemini-scan",
        "repository_context": {"entry_points": ["app.py"]},
        "findings": [],
        "business_context": {"domain": "E-Commerce", "criticality": "HIGH"},
        "business_intent_results": {
            "findings": [
                {
                    "rule_id": "REQ-001",
                    "rule": "Customers may cancel an order only before the order is shipped.",
                    "status": "PARTIAL",
                    "what": "Order cancellation lacks shipped status check",
                    "why": "Missing condition check order.status != 'SHIPPED'",
                    "how": "Add status check before setting CANCELLED",
                    "evidence": "file: order_service.py · function: cancel_order",
                    "file": "order_service.py",
                    "line_number": 12,
                    "score": 0.5,
                }
            ]
        }
    }

    agent_out = agent.run(sample_state)
    bi_res = agent_out.get("business_intent_results", {})
    grok_status = bi_res.get("grok_status")
    agent_reason = bi_res.get("agent_reason")
    ai_insights = agent_out.get("ai_business_insights", [])

    print(f"BusinessAgent grok_status: {grok_status}")
    print(f"BusinessAgent agent_reason: {agent_reason.encode('ascii', 'ignore').decode('ascii') if agent_reason else ''}")
    print(f"BusinessAgent ai_business_insights count: {len(ai_insights)}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print(f"1. Provider selected: {cfg.provider}")
    print(f"2. Model selected: {cfg.model}")
    print(f"3. Gemini connectivity: {'SUCCESS' if conn_success else 'FAILED'}")
    print(f"4. Exact error: {conn_error if conn_error else 'None'}")
    print(f"5. BusinessAgent called Gemini: {'YES' if grok_status == 'COMPLETED' else 'NO (' + str(grok_status) + ')'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
