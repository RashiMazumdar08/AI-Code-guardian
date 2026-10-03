import time
import json
from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest
from guardian.reasoning.schemas import parse_business_intent_response

def main():
    cfg = LLMConfig.from_env()
    print("=== TESTING EXACT BUSINESSAGENT PATH VIA REASONING GATEWAY ===")
    print("Provider:", cfg.provider)
    print("Model:", cfg.model)
    print("Base URL:", cfg.base_url)

    service = NemotronReasoningService(cfg)

    # Recreate the exact request BusinessAgent sends for REQ-002 / REQ-001 / REQ-003
    req = ReasoningRequest(
        task="business_intent",
        instruction="Analyze compliance for requirement: BR-002 — Parameterized SQL Queries.",
        schema_instruction="Output JSON with keys: 'verdict', 'confidence', 'reasoning', 'evidence_ids', 'missing_controls'.",
        evidence_block="Code file app.py line 677 executes SQL query directly.",
        business_block="BR-002: All database queries must use parameterized statements.",
        max_tokens=250, # The value used in BusinessAgent!
        temperature=0.2,
        agent="business",
        scan_id="test_diag_scan"
    )

    print("\n--- TEST 1: Request with max_tokens=250 (current BusinessAgent setting) ---")
    t0 = time.time()
    res250 = service.reason(req)
    dur250 = round((time.time() - t0) * 1000, 1)
    print(f"Gateway Result available: {res250.available} | latency: {dur250}ms")
    print(f"Error string: {res250.error}")
    if res250.response:
        print(f"Response problems: {res250.response.problems}")
        print(f"Response raw length: {len(res250.response.raw or '')}")
        print("Raw content snippet:")
        print(repr(res250.response.raw[:300] if res250.response.raw else ""))

    print("\n--- TEST 2: Request with max_tokens=1000 ---")
    req.max_tokens = 1000
    t0 = time.time()
    res1000 = service.reason(req)
    dur1000 = round((time.time() - t0) * 1000, 1)
    print(f"Gateway Result available: {res1000.available} | latency: {dur1000}ms")
    print(f"Error string: {res1000.error}")
    if res1000.response:
        print(f"Response problems: {res1000.response.problems}")
        print(f"Response raw length: {len(res1000.response.raw or '')}")
        print("Raw content snippet:")
        print(repr(res1000.response.raw[:500] if res1000.response.raw else ""))

if __name__ == "__main__":
    main()
