import time
import json
from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest
from guardian.reasoning.schemas import parse_business_intent_response, extract_json

def main():
    cfg = LLMConfig.from_env()
    print("=== TESTING COMPLETE NEMOTRON REASONING WITH SUFFICIENT TOKENS (800) ===")
    service = NemotronReasoningService(cfg)

    req_instruction = (
        "Semantically evaluate the supplied policy requirement against the implementation evidence.\n"
        "Return one verdict: COMPLIANT, VIOLATION, PARTIAL, or INSUFFICIENT_EVIDENCE.\n"
        "If no policy-relevant implementation evidence exists in the codebase, return INSUFFICIENT_EVIDENCE."
    )

    schema_inst = (
        'CRITICAL: After your brief internal reasoning, you MUST output a single valid JSON object strictly matching this schema:\n'
        '{\n'
        '  "summary": "<summary>",\n'
        '  "findings": [\n'
        '    {\n'
        '      "policy_id": "<policy_id>",\n'
        '      "verdict": "COMPLIANT|VIOLATION|PARTIAL|INSUFFICIENT_EVIDENCE",\n'
        '      "confidence": 0.95,\n'
        '      "reason": "<reason>",\n'
        '      "recommendation": "<recommendation>",\n'
        '      "missing_control": "",\n'
        '      "file": "workspace",\n'
        '      "line": 1,\n'
        '      "function": "",\n'
        '      "evidence_ids": ["E1"]\n'
        '    }\n'
        '  ]\n'
        '}'
    )

    req = ReasoningRequest(
        task="business_intent",
        agent="business",
        scan_id="test_diag_scan",
        instruction=req_instruction,
        schema_instruction=schema_inst,
        business_block="REQ-002: All database queries must use parameterized statements.",
        evidence_block="[E1] Code file app.py line 677 executes c.execute('SELECT * FROM users WHERE username = ' + input) directly.",
        max_tokens=800,
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
        print("Raw content tail (last 400 chars):")
        print(repr(res.response.raw[-400:] if res.response.raw else ""))
        if res.response.findings:
            print("\nParsed Finding 0:", res.response.findings[0].to_dict())

if __name__ == "__main__":
    main()
