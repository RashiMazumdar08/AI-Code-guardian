import time
import json
from guardian.llm.config import LLMConfig
from guardian.llm.nemotron import NemotronLLM
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest
from guardian.reasoning.schemas import parse_business_intent_response, extract_json

def main():
    cfg = LLMConfig.from_env()
    print("=== TESTING NEMOTRON WITH THINKING DISABLED OR PROMPT ADJUSTED ===")

    # Test A: LLMConfig with enable_thinking = False
    cfg_no_think = LLMConfig.from_env()
    cfg_no_think.enable_thinking = False

    service_no_think = NemotronReasoningService(cfg_no_think)

    schema_inst = (
        'Respond ONLY with a JSON object strictly matching this schema:\n'
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
        instruction="Semantically evaluate policy requirement REQ-002 against implementation evidence.",
        schema_instruction=schema_inst,
        business_block="REQ-002: All database queries must use parameterized statements.",
        evidence_block="Code file app.py line 677 executes c.execute('SELECT * FROM users WHERE username = ' + input) directly.",
        max_tokens=400,
        temperature=0.1,
    )

    print("\n--- TEST A: enable_thinking = False ---")
    t0 = time.time()
    res_a = service_no_think.reason(req)
    dur_a = round((time.time() - t0) * 1000, 1)
    print(f"Result available: {res_a.available} | latency: {dur_a}ms")
    print(f"Error: {res_a.error}")
    if res_a.response:
        print("Response OK:", res_a.response.ok)
        print("Response problems:", res_a.response.problems)
        print("Findings count:", len(res_a.response.findings))
        print("Raw content:")
        print(res_a.response.raw)
        if res_a.response.findings:
            print("\nParsed Finding 0:", res_a.response.findings[0].to_dict())

if __name__ == "__main__":
    main()
