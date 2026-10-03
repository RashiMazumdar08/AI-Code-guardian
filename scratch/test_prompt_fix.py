import time
from guardian.llm.config import LLMConfig
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest

def main():
    cfg = LLMConfig.from_env()
    print("=== TESTING PROMPT-ONLY FIX FOR NEMOTRON ===")
    service = NemotronReasoningService(cfg)

    prompt_instruction = (
        "Semantically evaluate the supplied policy requirement against the implementation evidence.\n"
        "Return one verdict: COMPLIANT, VIOLATION, PARTIAL, or INSUFFICIENT_EVIDENCE.\n"
        "If no policy-relevant implementation evidence exists in the codebase, return INSUFFICIENT_EVIDENCE.\n\n"
        "CRITICAL RESPONSE FORMAT INSTRUCTIONS:\n"
        "Respond ONLY with a single valid JSON object.\n"
        "The first character of your response must be '{'.\n"
        "Do not output thinking steps.\n"
        "Do not output analysis before the JSON.\n"
        "Do not output analysis after the JSON.\n"
        "Do not use Markdown code fences.\n"
        "Do not include ```json.\n"
        "Do not include a preamble or explanation outside the JSON object."
    )

    schema_inst = (
        'Respond ONLY with a single valid JSON object strictly matching this schema:\n'
        '{\n'
        '  "summary": "<summary>",\n'
        '  "findings": [\n'
        '    {\n'
        '      "policy_id": "REQ-002",\n'
        '      "verdict": "COMPLIANT",\n'
        '      "confidence": 0.95,\n'
        '      "reason": "<reason>",\n'
        '      "recommendation": "<recommendation>",\n'
        '      "missing_control": "",\n'
        '      "file": "app.py",\n'
        '      "line": 677,\n'
        '      "function": "login",\n'
        '      "evidence_ids": ["E1"]\n'
        '    }\n'
        '  ]\n'
        '}'
    )

    req = ReasoningRequest(
        task="business_intent",
        agent="business",
        scan_id="test_diag_scan",
        instruction=prompt_instruction,
        schema_instruction=schema_inst,
        business_block="REQ-002: All database queries must use parameterized statements.",
        evidence_block="Code file app.py line 677 executes c.execute('SELECT * FROM users WHERE username = ' + input) directly.",
        max_tokens=350,
        temperature=0.1,
    )

    t0 = time.time()
    res = service.reason(req)
    dur = round((time.time() - t0) * 1000, 1)

    print(f"Gateway Result available: {res.available} | latency: {dur}ms")
    print(f"Error: {res.error}")
    if res.response:
        print(f"Response problems: {res.response.problems}")
        print("Response OK:", res.response.ok)
        print("Findings count:", len(res.response.findings))
        print("Raw content:")
        print(res.response.raw)
        if res.response.findings:
            print("\nParsed Finding 0:", res.response.findings[0].to_dict())

if __name__ == "__main__":
    main()
