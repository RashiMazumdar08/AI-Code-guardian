import sys
import os
sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()
os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"

from pathlib import Path
from unittest.mock import patch
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.agents.security.agent import SecurityAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest

target_dir = Path("tests/fixtures/dv-bookshop_raw/dv-bookshop-main").resolve()

# 1. Total workspace functions & ranking
ws_profiles = RuleMatcher._profiles_from_workspace(target_dir)
print(f"=== TRACE DIAGNOSTIC: DV-BOOKSHOP ===")
print(f"1. Total workspace functions discovered: {len(ws_profiles)}")

# Sort by security score descending
sorted_profiles = sorted(ws_profiles, key=lambda p: getattr(p, "security_score", 0.0), reverse=True)

print("\n=== 2. Top 20 Functions Ranked by Security Score ===")
for idx, p in enumerate(sorted_profiles[:20], 1):
    snip_lower = (p.code_snippet or "").lower()
    has_route = any(k in snip_lower for k in ["@app.route", "route("])
    has_auth = any(k in snip_lower for k in ["login_required", "auth", "session", "admin_required"])
    has_params = any(k in (p.function_name + " " + snip_lower) for k in ["user_id", "order_id", "id", "token"])
    has_db = any(k in snip_lower for k in ["execute", "select", "db", "query", "cursor"])
    
    print(f"{idx:2d}. Score: {p.security_score:4.1f} | File: {p.file}:{p.line} | Func: {p.function_name}")
    print(f"    Signals -> Route: {has_route} | Auth: {has_auth} | Params: {has_params} | DB: {has_db}")

print("\n=== 3. Top 5 Candidates Sent to Grok ===")
top_5 = sorted_profiles[:5]
for idx, p in enumerate(top_5, 1):
    print(f"Candidate #{idx}: {p.function_name} ({p.file}:{p.line}) - Score: {p.security_score}")

print("\n=== 4. Bounded Source Snippets for Top 5 Candidates ===")
for idx, p in enumerate(top_5, 1):
    print(f"\n--- Candidate #{idx}: {p.function_name} ({p.file}:{p.line}) ---")
    print(p.code_snippet)

print("\n=== 5. Check Known Security-Sensitive Endpoint (profile / D1_idor_profile) ===")
profile_p = next((p for p in ws_profiles if p.function_name == "profile"), None)
if profile_p:
    p_rank = sorted_profiles.index(profile_p) + 1
    print(f"Discovered: YES | Func: profile ({profile_p.file}:{profile_p.line})")
    print(f"Security Score: {profile_p.security_score}")
    print(f"Rank in Workspace: #{p_rank} of {len(ws_profiles)}")
    print(f"Selected in Top 5: {'YES' if p_rank <= 5 else 'NO'}")
else:
    print("Discovered: NO")

# 6. Run SecurityAgent and capture evidence blocks
state = create_initial_state(
    scan_id="trace-dv-bookshop-scan",
    findings=[],
    evidence=[],
    repository_profile={
        "repo_path": str(target_dir),
        "total_files": len(os.listdir(target_dir)),
    }
)

captured_requests = []
def mock_reason_intercept(request):
    captured_requests.append(request)
    cfg = ReasoningGateway().config
    service = ReasoningGateway(config=cfg)
    return service.reason(request)

with patch("guardian.reasoning.gateway.ReasoningGateway.reason", side_effect=mock_reason_intercept):
    agent = SecurityAgent()
    res = agent.run(state)

print("\n=== 6. Exact Evidence Block Passed to SecurityAgent Reasoning Call ===")
if captured_requests:
    req = captured_requests[0]
    print("Task:", req.task)
    print("Instruction:", req.instruction)
    print("\nEvidence Block:")
    print(str(req.evidence_block).encode('ascii', 'ignore').decode('ascii'))

print("\n=== 7. Repository Context / Topology Availability ===")
repo_ctx = res.get("repository_context", {})
print("Languages:", repo_ctx.get("languages"))
print("Frameworks:", repo_ctx.get("frameworks"))
print("Public APIs:", len(repo_ctx.get("public_apis", [])))
print("Auth Modules:", repo_ctx.get("auth_modules"))
print("DB Layers:", repo_ctx.get("database_layers"))

print("\n=== 8. Cross-File Relationships Availability ===")
print("Repository Graph in State:", bool(state.get("repository_graph")))
print("Call Topology in State:", "None passed to SecurityAgent reasoning prompt")

print("\n=== 9. Grok Reasoning Diagnostic Result ===")
sec_ctx = res.get("security_context", {})
print("Grok Status:", sec_ctx.get("grok_status"))
print("Agent Reason:", str(sec_ctx.get("agent_reason")).encode('ascii', 'ignore').decode('ascii'))
ai_insights = res.get("ai_security_insights", [])
print(f"AI Findings Extracted: {len(ai_insights)}")

for idx, insight in enumerate(ai_insights, 1):
    print(f"\nAI Finding #{idx}:")
    print(f"  Rule ID: {insight.get('rule_id')}")
    print(f"  Title: {insight.get('title')}")
    print(f"  File: {insight.get('file_path') or insight.get('file')}:{insight.get('line')}")
    print(f"  Description: {str(insight.get('description')).encode('ascii', 'ignore').decode('ascii')}")
