import sys
import os
sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()
os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"

from pathlib import Path
from guardian.agents.security.agent import SecurityAgent
from guardian.orchestrator.state import create_initial_state

target_dir = Path("tests/fixtures/multi_file_app").resolve()

state = create_initial_state(
    scan_id="test-multi-file-app-scan",
    findings=[],
    evidence=[],
    repository_profile={
        "repo_path": str(target_dir),
        "total_files": 4,
    }
)

agent = SecurityAgent()
res = agent.run(state)

print("=== MULTI-FILE APP AGENTIC SECURITY SCAN RESULTS ===")
print("Completed Agents:", res.get("completed_agents"))

sec_ctx = res.get("security_context", {})
print("\n--- Security Context ---")
print("Total Findings:", sec_ctx.get("total_findings"))
print("Grok Status:", sec_ctx.get("grok_status"))
print("Agent Reason:", str(sec_ctx.get("agent_reason")).encode('ascii', 'ignore').decode('ascii'))

ai_insights = res.get("ai_security_insights", [])
print(f"\n--- AI Security Insights ({len(ai_insights)}) ---")
for idx, insight in enumerate(ai_insights, 1):
    print(f"\nAI Insight #{idx}:")
    print(f"  Finding ID: {insight.get('finding_id')}")
    print(f"  Rule ID: {insight.get('rule_id')}")
    print(f"  Title: {insight.get('title')}")
    print(f"  Severity: {insight.get('severity')}")
    print(f"  Category: {insight.get('category')}")
    print(f"  Source: {insight.get('source')}")
    print(f"  Engine: {insight.get('engine')}")
    print(f"  File: {insight.get('file_path') or insight.get('file')}:{insight.get('line')}")
    print(f"  Description: {str(insight.get('description')).encode('ascii', 'ignore').decode('ascii')}")
    print(f"  Recommendation: {str(insight.get('recommendation')).encode('ascii', 'ignore').decode('ascii')}")
