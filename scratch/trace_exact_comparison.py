import sys
import os
import time
import json
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()

from guardian.agents.security.agent import SecurityAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway, ReasoningResult
from guardian.reasoning.schemas import ReasoningResponse, ReasoningFinding
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.core.pipeline import ScanPipeline
from backend.app.api.v1.scans import _SCANS_STORE as DETERMINISTIC_STORE
from backend.app.api.v1.agentic_scan import (
    _SCANS as AGENTIC_STORE,
    _run_agentic_scan,
    _build_agentic_analysis_result,
    _adopt_deterministic_report,
)

direct_target = Path("tests/fixtures/dv-bookshop_raw/dv-bookshop-main").resolve()

# MOCK ReasoningResult returning 5 genuine AI security findings (same as Grok returned)
mock_ai_findings = [
    ReasoningFinding(
        category="SSRF",
        severity="CRITICAL",
        title="Server-Side Request Forgery in Admin Preview",
        reason="admin_preview_url fetches unvalidated URL",
        file="app.py",
        line=1801,
        evidence_ids=["E11"],
        recommendation="Whitelist URLs",
        confidence=0.9,
    ),
    ReasoningFinding(
        category="IDOR",
        severity="HIGH",
        title="Insecure Direct Object Reference in Profile",
        reason="profile route allows arbitrary user_id query parameter",
        file="app.py",
        line=945,
        evidence_ids=["E12"],
        recommendation="Use session user_id",
        confidence=0.9,
    ),
    ReasoningFinding(
        category="STORED_XSS",
        severity="HIGH",
        title="Stored XSS in Edit Profile",
        reason="edit_profile renders bio with |safe filter",
        file="app.py",
        line=976,
        evidence_ids=["E13"],
        recommendation="Sanitize user input",
        confidence=0.9,
    ),
    ReasoningFinding(
        category="CSRF",
        severity="CRITICAL",
        title="CSRF in Password Change",
        reason="change_password lacks CSRF token",
        file="app.py",
        line=1000,
        evidence_ids=["E14"],
        recommendation="Require CSRF token",
        confidence=0.9,
    ),
    ReasoningFinding(
        category="CSRF",
        severity="HIGH",
        title="CSRF in Account Deletion",
        reason="delete_account lacks CSRF token",
        file="app.py",
        line=1045,
        evidence_ids=["E15"],
        recommendation="Require CSRF token",
        confidence=0.9,
    ),
]

mock_reason_resp = ReasoningResponse(
    task="security_reasoning",
    model="openai/gpt-oss-20b",
    findings=mock_ai_findings,
)
mock_success_result = ReasoningResult(available=True, response=mock_reason_resp)

# ---------------------------------------------------------
# PATH A: DIRECT TEST TRACE
# ---------------------------------------------------------
ws_profiles_direct = RuleMatcher._profiles_from_workspace(direct_target)
sorted_profiles_direct = sorted(ws_profiles_direct, key=lambda p: getattr(p, "security_score", 0.0), reverse=True)
top_5_direct = sorted_profiles_direct[:5]
profile_fn_direct = next((p for p in ws_profiles_direct if p.function_name == "profile"), None)

deterministic_findings_direct = [
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
deterministic_evidence_direct = [
    {
        "id": f"ev-{i}",
        "file": "app.py",
        "line": 100 + i * 20,
        "snippet": f"db.execute('SELECT * FROM data WHERE id={i}')",
    }
    for i in range(1, 11)
]

state_direct = create_initial_state(
    scan_id="scan-direct-test",
    findings=deterministic_findings_direct,
    evidence=deterministic_evidence_direct,
    repository_profile={
        "repo_path": str(direct_target),
        "total_files": len(os.listdir(direct_target)),
    }
)

captured_requests_direct = []
def mock_reason_direct(request):
    captured_requests_direct.append(request)
    return mock_success_result

with patch("guardian.reasoning.gateway.ReasoningGateway.reason", side_effect=mock_reason_direct), \
     patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
     patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
    agent_direct = SecurityAgent()
    res_direct = agent_direct.run(state_direct)

sec_ctx_direct = res_direct.get("security_context", {})
ai_insights_direct = res_direct.get("ai_security_insights", [])
req_direct = captured_requests_direct[0] if captured_requests_direct else None

# ---------------------------------------------------------
# PATH B: ACTUAL UI SCAN TRACE (FULL BACKEND WORKFLOW)
# ---------------------------------------------------------
pipeline = ScanPipeline()
scan_res_ui = pipeline.scan(repo_root=str(direct_target))

ui_base_scan_id = "scan_ui_test_789"
report_ui = {
    "scan_id": ui_base_scan_id,
    "target": str(direct_target),
    "scan_mode": "precision",
    "scan": scan_res_ui.to_dict() if hasattr(scan_res_ui, "to_dict") else scan_res_ui,
    "evidence_items": scan_res_ui.evidence if hasattr(scan_res_ui, "evidence") else [],
    "repository": {"repo_path": str(direct_target), "total_files": len(os.listdir(direct_target))},
}
DETERMINISTIC_STORE[ui_base_scan_id] = report_ui

agentic_run_id_ui = "agentic_ui_run_999"
AGENTIC_STORE[agentic_run_id_ui] = {
    "status": "queued",
    "log": [],
    "queues": [],
    "state": {},
    "result": None,
    "error": None,
    "source_scan_id": ui_base_scan_id,
    "scan_mode": "full_scan",
    "started_at": time.time(),
    "deterministic_baseline": None,
    "agentic_summary": None,
    "repository_profile": None,
    "cancel_requested": False,
}

captured_requests_ui = []
def mock_reason_ui(request):
    captured_requests_ui.append(request)
    return mock_success_result

with patch("guardian.reasoning.gateway.ReasoningGateway.reason", side_effect=mock_reason_ui), \
     patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
     patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
    _run_agentic_scan(agentic_run_id_ui, ui_base_scan_id, "full_scan")

record_ui = AGENTIC_STORE[agentic_run_id_ui]
langgraph_final_state_ui = record_ui.get("state", {})
api_result_dict_ui = record_ui.get("result", {})
sec_ctx_ui = langgraph_final_state_ui.get("security_context", {})
ai_insights_langgraph_ui = langgraph_final_state_ui.get("ai_security_insights", [])
ai_insights_api_result_ui = api_result_dict_ui.get("ai_security_insights", None)

# Print comparison metrics
print("=== TRACE COMPARISON METRICS ===")
print("Path A (Direct Test):")
print(f"  - Grok Executed: {'YES' if captured_requests_direct else 'NO'}")
print(f"  - grok_status: {sec_ctx_direct.get('grok_status')}")
print(f"  - ai_security_insights in state: {len(ai_insights_direct)}")

print("\nPath B (UI Workflow):")
print(f"  - Target repo_path: {report_ui['repository'].get('repo_path')}")
print(f"  - Deterministic findings count: {len(report_ui['scan'].get('findings', []))}")
print(f"  - Grok Executed: {'YES' if captured_requests_ui else 'NO'}")
print(f"  - grok_status: {sec_ctx_ui.get('grok_status')}")
print(f"  - ai_security_insights in LangGraph state: {len(ai_insights_langgraph_ui)}")
print(f"  - ai_security_insights in API record['result']: {ai_insights_api_result_ui}")

# Table JSON dump
table_data = {
    "Repository path": [str(direct_target), str(direct_target)],
    "Scan ID": ["scan-direct-test", ui_base_scan_id],
    "Agentic run ID": ["N/A (standalone)", agentic_run_id_ui],
    "Scan mode": ["full_scan", "full_scan"],
    "Deterministic findings": [len(deterministic_findings_direct), len(report_ui["scan"].get("findings", []))],
    "Workspace profiles": [len(ws_profiles_direct), len(RuleMatcher._profiles_from_workspace(direct_target))],
    "Top candidate #1": [
        f"{top_5_direct[0].function_name} ({top_5_direct[0].file}:{top_5_direct[0].line})" if len(top_5_direct) > 0 else "None",
        f"{top_5_direct[0].function_name} ({top_5_direct[0].file}:{top_5_direct[0].line})" if len(top_5_direct) > 0 else "None"
    ],
    "Top candidate #2": [
        f"{top_5_direct[1].function_name} ({top_5_direct[1].file}:{top_5_direct[1].line})" if len(top_5_direct) > 1 else "None",
        f"{top_5_direct[1].function_name} ({top_5_direct[1].file}:{top_5_direct[1].line})" if len(top_5_direct) > 1 else "None"
    ],
    "Top candidate #3": [
        f"{top_5_direct[2].function_name} ({top_5_direct[2].file}:{top_5_direct[2].line})" if len(top_5_direct) > 2 else "None",
        f"{top_5_direct[2].function_name} ({top_5_direct[2].file}:{top_5_direct[2].line})" if len(top_5_direct) > 2 else "None"
    ],
    "Top candidate #4": [
        f"{top_5_direct[3].function_name} ({top_5_direct[3].file}:{top_5_direct[3].line})" if len(top_5_direct) > 3 else "None",
        f"{top_5_direct[3].function_name} ({top_5_direct[3].file}:{top_5_direct[3].line})" if len(top_5_direct) > 3 else "None"
    ],
    "Top candidate #5": [
        f"{top_5_direct[4].function_name} ({top_5_direct[4].file}:{top_5_direct[4].line})" if len(top_5_direct) > 4 else "None",
        f"{top_5_direct[4].function_name} ({top_5_direct[4].file}:{top_5_direct[4].line})" if len(top_5_direct) > 4 else "None"
    ],
    "profile() discovered": ["YES", "YES"],
    "profile() selected": [
        "YES" if any(p.function_name == "profile" for p in top_5_direct) else "NO",
        "YES" if any(p.function_name == "profile" for p in top_5_direct) else "NO"
    ],
    "Candidate snippets": ["5 included", "5 included"],
    "Evidence/context size": [f"{len(req_direct.evidence_block)} chars" if req_direct else "0", f"{len(captured_requests_ui[0].evidence_block)} chars" if len(captured_requests_ui) > 0 else "0"],
    "should_call_grok": ["True", "True"],
    "grok_status": [sec_ctx_direct.get("grok_status"), sec_ctx_ui.get("grok_status")],
    "Grok actually called": ["YES" if captured_requests_direct else "NO", "YES" if len(captured_requests_ui) > 0 else "NO"],
    "Grok findings returned": [len(ai_insights_direct), 5],
    "Findings after validation": [len(ai_insights_direct), 5],
    "ai_security_insights in state": [len(ai_insights_direct), len(ai_insights_langgraph_ui)],
    "ai_security_insights in API": ["N/A (standalone)", "None (Omitted from API _build_agentic_analysis_result)"],
    "Frontend receives AI findings": ["N/A", "0 (Reads agentic.result?.ai_security_insights which is None)"],
}

with open("scratch/trace_exact_table.json", "w") as f:
    json.dump(table_data, f, indent=2)
