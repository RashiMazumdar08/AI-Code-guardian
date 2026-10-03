import time
import json
from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest

def main():
    cfg = LLMConfig.from_env()
    print("=== TESTING SYSTEM_ROLE JSON MANDATE WITH NEMOTRON ===")
    service = NemotronReasoningService(cfg)

    strict_system_role = (
        "You are a senior application security engineer performing contextual analysis.\n"
        "CRITICAL FORMAT RULES:\n"
        "1. Respond ONLY with a single valid JSON object.\n"
        "2. The first character of your response must be '{'.\n"
        "3. Do not output thinking steps.\n"
        "4. Do not output analysis before the JSON.\n"
        "5. Do not output analysis after the JSON.\n"
        "6. Do not use Markdown code fences.\n"
        "7. Do not include ```json.\n"
        "8. Do not include a preamble or explanation outside the JSON object."
    )

    req = ReasoningRequest(
        task="business_intent",
        agent="business",
        scan_id="test_diag_scan",
        system_role=strict_system_role,
        instruction="Semantically evaluate policy REQ-002 against implementation evidence.",
        schema_instruction='Return JSON: {"summary": "Analysis complete", "findings": [{"policy_id": "REQ-002", "verdict": "VIOLATION", "confidence": 0.95, "reason": "Unparameterized query", "recommendation": "Use params", "missing_control": "parameterized_query", "file": "app.py", "line": 677, "function": "login", "evidence_ids": ["E1"]}]}',
        business_block="REQ-002: All database queries must use parameterized statements.",
        evidence_block="[E1] Code file app.py line 677 executes c.execute('SELECT * FROM users WHERE username = ' + input) directly.",
        max_tokens=400,
        temperature=0.1,
    )

    t0 = time.time()
    res = service.reason(req)
    dur = round((time.time() - t0) * 1000, 1)

    print(f"Gateway Result available: {res.available} | latency: {dur}ms")
    print(f"Error: {res.error}")
    if res.response:
        print("Response OK:", res.response.ok)
        print("Response problems:", res.response.problems)
        print("Findings count:", len(res.response.findings))
        print("Raw content:")
        print(res.response.raw)
        if res.response.findings:
            print("\nParsed Finding 0:", res.response.findings[0].to_dict())

if __name__ == "__main__":
    main()
