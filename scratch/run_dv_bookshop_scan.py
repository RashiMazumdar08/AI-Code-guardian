import sys
import os
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()
os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"

from guardian.agents.security.agent import SecurityAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway
from unittest.mock import patch

target_dir = Path("tests/fixtures/dv-bookshop_raw/dv-bookshop-main").resolve()

# Simulate 10 deterministic findings (as observed in full DV-Bookshop scan)
deterministic_findings = [
    {
        "finding_id": f"det-f-{i}",
        "rule_id": "SEC-SQL-INJECTION" if i % 2 == 0 else "SEC-AUTH-CHECK",
        "title": f"Deterministic SAST Finding #{i}",
        "severity": "HIGH" if i <= 3 else "MEDIUM",
        "confidence": 0.95,
        "file": "app.py",
        "line": 100 + i * 20,
        "evidence_id": f"ev-{i}",
        "snippet": f"db.execute('SELECT * FROM data WHERE id={i}')",
    }
    for i in range(1, 11)
]

deterministic_evidence = [
    {
        "id": f"ev-{i}",
        "file": "app.py",
        "line": 100 + i * 20,
        "snippet": f"db.execute('SELECT * FROM data WHERE id={i}')",
    }
    for i in range(1, 11)
]

state = create_initial_state(
    scan_id="test-dv-bookshop-scan-post-fix",
    findings=deterministic_findings,
    evidence=deterministic_evidence,
    repository_profile={
        "repo_path": str(target_dir),
        "total_files": len(os.listdir(target_dir)),
    }
)

captured_requests = []
original_reason = ReasoningGateway.reason

def mock_reason_intercept(self, request):
    captured_requests.append(request)
    return original_reason(self, request)

start_time = time.time()
with patch.object(ReasoningGateway, "reason", side_effect=mock_reason_intercept, autospec=True):
    agent = SecurityAgent()
    res = agent.run(state)
elapsed_time = time.time() - start_time

print("=== DV-BOOKSHOP SCAN POST-FIX METRICS ===")
sec_ctx = res.get("security_context", {})
ai_insights = res.get("ai_security_insights", [])

print(f"Deterministic Findings Count: {len(deterministic_findings)}")
print(f"Grok Status: {sec_ctx.get('grok_status')}")
print(f"Execution Time: {elapsed_time:.2f} seconds")

if captured_requests:
    req = captured_requests[0]
    ev_block = req.evidence_block
    ev_lines = ev_block.split("\n")
    print(f"Context Evidence Line Count: {len(ev_lines)}")
    print(f"Total Context Size (chars): {len(ev_block)}")
    
    # Count how many candidate profiles were appended
    candidates_included = [line for line in ev_lines if line.startswith("[E") and "function:" in line]
    print(f"Included Workspace Candidates Count: {len(candidates_included)}")
    print("\n--- Workspace Candidate Context Included in Request ---")
    for cand in candidates_included:
        print("  ", cand[:120])
    
    # Check if profile() candidate (profile at app.py:945) is in context
    has_profile_fn = "profile" in ev_block and "app.py" in ev_block
    print(f"\nDoes context include app.py profile() candidate? {'YES' if has_profile_fn else 'NO'}")

print(f"\nAI Findings Produced: {len(ai_insights)}")
for idx, insight in enumerate(ai_insights, 1):
    print(f"\nAI Finding #{idx}:")
    print(f"  Rule ID: {insight.get('rule_id')}")
    print(f"  Title: {insight.get('title')}")
    print(f"  Severity: {insight.get('severity')}")
    print(f"  File: {insight.get('file_path') or insight.get('file')}:{insight.get('line')}")
    print(f"  Description: {str(insight.get('description')).encode('ascii', 'ignore').decode('ascii')}")
    print(f"  Recommendation: {str(insight.get('recommendation')).encode('ascii', 'ignore').decode('ascii')}")
