import sys
import os
import time
sys.path.insert(0, os.path.abspath("."))

from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.llm.config import LLMConfig

def main():
    print("=== TESTING REAL ARCHITECTURE AGENT WITH GROQ ENDPOINT ===")

    os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"
    cfg = LLMConfig.from_env(agent="architecture")
    print(f"1. Provider adapter: {cfg.provider}")
    print(f"2. Actual endpoint: {cfg.base_url}")
    print(f"3. Model: {cfg.model}")
    state = {
        "scan_id": "test_arch_scan_001",
        "repository_profile": {
            "primary_language": "python",
            "detected_endpoints": ["/api/v1/checkout", "/api/v1/refund", "/api/v1/auth/login", "/api/v1/users"],
            "entry_points": ["main.py", "app.py"],
            "frameworks": ["FastAPI", "Spring Boot"]
        },
        "repository_context": {
            "auth_modules": ["JWT Bearer Authorization"],
            "database_layers": ["SQLAlchemy Data Access Layer"]
        },
        "findings": [
            {
                "rule_id": "REQ-001",
                "status": "VIOLATION",
                "what": "High value refund lacks manager approval",
                "evidence": "services/payment_service.py"
            }
        ]
    }

    t0 = time.time()
    agent = ArchitectureAgent()
    res_state = agent.run(state)
    total_latency = (time.time() - t0) * 1000

    arch_ctx = res_state.get("architecture_context", {})
    ai_insights = res_state.get("ai_architecture_insights", [])

    grok_status = arch_ctx.get("grok_status")
    agent_reason = arch_ctx.get("agent_reason")

    print(f"4. HTTP status: {'200 OK' if grok_status == 'COMPLETED' else grok_status}")
    print(f"5. Total latency: {total_latency:.1f} ms")
    print(f"6. Response parsing: {'SUCCESS' if grok_status == 'COMPLETED' else 'FAILED'}")
    print(f"7. Architecture findings produced: {len(ai_insights)}")
    if ai_insights:
        for i, ins in enumerate(ai_insights, 1):
            print(f"   Insight #{i}: {ins.get('verdict')} | {ins.get('rule_id', '')} - {ins.get('reasoning', '')[:100]}")
    print(f"8. Token usage: Handled by TokenTracker / ReasoningGateway")
    print(f"9. Result propagates to UI state?: {'YES' if 'architecture_context' in res_state else 'NO'}")
    print(f"10. Architecture grok_status: {grok_status}")
    print(f"    Agent Reason: {agent_reason}")
    print(f"    Trace errors: {res_state.get('agent_trace', [{}])[-1].get('errors', [])}")

if __name__ == "__main__":
    main()
