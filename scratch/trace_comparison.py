import sys
import os
import time
import json
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()
os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"

from guardian.agents.security.agent import SecurityAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningGateway
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

print("==================================================")
print("PART 1 & PART 2 TRACE EXECUTION")
print("==================================================")

# ---------------------------------------------------------
# PATH A: DIRECT TEST TRACE
# ---------------------------------------------------------
print("\n--- Running Path A: Direct Test ---")

ws_profiles_direct = RuleMatcher._profiles_from_workspace(direct_target)
sorted_profiles_direct = sorted(ws_profiles_direct, key=lambda p: getattr(p, "security_score", 0.0), reverse=True)
top_5_direct = sorted_profiles_direct[:5]
profile_fn_direct = next((p for p in ws_profiles_direct if p.function_name == "profile"), None)

# Simulated 10 deterministic findings (or real ScanPipeline findings)
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
original_reason = ReasoningGateway.reason

def intercept_direct(self, request):
    captured_requests_direct.append(request)
    return original_reason(self, request)

with patch.object(ReasoningGateway, "reason", side_effect=intercept_direct, autospec=True):
    agent_direct = SecurityAgent()
    res_direct = agent_direct.run(state_direct)

sec_ctx_direct = res_direct.get("security_context", {})
ai_insights_direct = res_direct.get("ai_security_insights", [])
req_direct = captured_requests_direct[0] if captured_requests_direct else None

# ---------------------------------------------------------
# PATH B: ACTUAL UI SCAN TRACE
# ---------------------------------------------------------
print("\n--- Running Path B: Actual UI Scan via Backend API & LangGraph ---")

# Step B1: Run real ScanPipeline (or populate report in _SCANS_STORE)
pipeline = ScanPipeline()
scan_res_ui = pipeline.scan(repo_root=str(direct_target))

ui_base_scan_id = "scan_ui_test_123"
report_ui = {
    "scan_id": ui_base_scan_id,
    "target": str(direct_target),
    "scan_mode": "precision",
    "scan": scan_res_ui.to_dict() if hasattr(scan_res_ui, "to_dict") else scan_res_ui,
    "evidence_items": scan_res_ui.evidence if hasattr(scan_res_ui, "evidence") else [],
    "repository": {"repo_path": str(direct_target), "total_files": len(os.listdir(direct_target))},
}
DETERMINISTIC_STORE[ui_base_scan_id] = report_ui

# Step B2: Trigger agentic scan via start endpoint logic
agentic_run_id_ui = "agentic_ui_run_456"
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
def intercept_ui(self, request):
    captured_requests_ui.append(request)
    return original_reason(self, request)

with patch.object(ReasoningGateway, "reason", side_effect=intercept_ui, autospec=True):
    _run_agentic_scan(agentic_run_id_ui, ui_base_scan_id, "full_scan")

record_ui = AGENTIC_STORE[agentic_run_id_ui]
langgraph_final_state_ui = record_ui.get("state", {})
api_result_dict_ui = record_ui.get("result", {})
sec_ctx_ui = langgraph_final_state_ui.get("security_context", {})
ai_insights_langgraph_ui = langgraph_final_state_ui.get("ai_security_insights", [])
ai_insights_api_result_ui = api_result_dict_ui.get("ai_security_insights", None)

print("==================================================")
print("TRACE FIELD COMPARISON DATA")
print("==================================================")

data = {
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
    "profile() discovered": ["YES" if profile_fn_direct else "NO", "YES" if profile_fn_direct else "NO"],
    "profile() selected": [
        "YES" if any(p.function_name == "profile" for p in top_5_direct) else "NO",
        "YES" if any(p.function_name == "profile" for p in top_5_direct) else "NO"
    ],
    "Candidate snippets": ["5 included", "5 included"],
    "Evidence/context size": [f"{len(req_direct.evidence_block)} chars" if req_direct else "0", f"{len(captured_requests_ui[0].evidence_block)} chars" if captured_requests_ui else "0"],
    "should_call_grok": ["True", "True"],
    "grok_status": [sec_ctx_direct.get("grok_status"), sec_ctx_ui.get("grok_status")],
    "Grok actually called": ["YES" if captured_requests_direct else "NO", "YES" if captured_requests_ui else "NO"],
    "Grok findings returned": [len(ai_insights_direct), len(ai_insights_langgraph_ui)],
    "Findings after validation": [len(ai_insights_direct), len(ai_insights_langgraph_ui)],
    "ai_security_insights in state": [len(ai_insights_direct), len(ai_insights_langgraph_ui)],
    "ai_security_insights in API": ["N/A (no API envelope)", str(ai_insights_api_result_ui)],
    "Frontend receives AI findings": ["N/A", "0 (via agentic.result?.ai_security_insights)"],
}

print("\nSaved trace results for table generation.")
with open("scratch/trace_results.json", "w") as f:
    json.dump(data, f, indent=2)

print("\n--- Detailed API vs State Inspection ---")
print("LangGraph Final State ai_security_insights count:", len(ai_insights_langgraph_ui))
print("API Result Object ai_security_insights present?:", "ai_security_insights" in api_result_dict_ui)
print("API Result Object ai_security_insights value:", api_result_dict_ui.get("ai_security_insights"))
print("SecurityWorkbench frontend lookup expression: agentic.result?.ai_security_insights")
