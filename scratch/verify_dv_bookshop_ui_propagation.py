import sys
import os
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()
os.environ["NVIDIA_MODEL"] = "openai/gpt-oss-20b"

from guardian.core.pipeline import ScanPipeline
from guardian.reasoning.gateway import ReasoningGateway
from backend.app.api.v1.scans import _SCANS_STORE as DETERMINISTIC_STORE
from backend.app.api.v1.agentic_scan import (
    _SCANS as AGENTIC_STORE,
    _run_agentic_scan,
)

target_dir = Path("tests/fixtures/dv-bookshop_raw/dv-bookshop-main").resolve()

print("=== RUNNING DV-BOOKSHOP FULL SCAN WITH API PROPAGATION FIX ===")

# 1. Deterministic Scan
pipeline = ScanPipeline()
scan_res = pipeline.scan(repo_root=str(target_dir))
raw_findings = scan_res.to_dict().get("scan", {}).get("findings", []) if hasattr(scan_res, "to_dict") else []

ui_base_scan_id = "scan_dv_bookshop_verify"
report_ui = {
    "scan_id": ui_base_scan_id,
    "target": str(target_dir),
    "scan_mode": "precision",
    "scan": scan_res.to_dict() if hasattr(scan_res, "to_dict") else scan_res,
    "evidence_items": scan_res.evidence if hasattr(scan_res, "evidence") else [],
    "repository": {"repo_path": str(target_dir), "total_files": len(os.listdir(target_dir))},
}
DETERMINISTIC_STORE[ui_base_scan_id] = report_ui

# 2. Trigger Agentic Scan
agentic_run_id = "agentic_dv_bookshop_verify"
AGENTIC_STORE[agentic_run_id] = {
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

captured_requests = []
original_reason = ReasoningGateway.reason

def mock_reason_intercept(self, request):
    captured_requests.append(request)
    return original_reason(self, request)

from unittest.mock import patch
with patch.object(ReasoningGateway, "reason", side_effect=mock_reason_intercept, autospec=True):
    _run_agentic_scan(agentic_run_id, ui_base_scan_id, "full_scan")

record = AGENTIC_STORE[agentic_run_id]
final_state = record.get("state", {})
api_result = record.get("result", {})

sec_ctx = final_state.get("security_context", {})
langgraph_insights = final_state.get("ai_security_insights", [])
api_insights = api_result.get("ai_security_insights", [])
sec_enrichment_insights = api_result.get("security_enrichment", {}).get("ai_security_insights", [])

print("\n=== VERIFICATION METRICS FOR DV-BOOKSHOP SCAN ===")
print(f"Deterministic Findings Count: {len(raw_findings)}")
print(f"SecurityAgent Grok Status: {sec_ctx.get('grok_status')}")
print(f"LangGraph State ai_security_insights Count: {len(langgraph_insights)}")
print(f"API result.ai_security_insights Count: {len(api_insights)}")
print(f"API result.security_enrichment.ai_security_insights Count: {len(sec_enrichment_insights)}")

# Simulate frontend lookup: agentic.result?.ai_security_insights || []
frontend_received_insights = api_result.get("ai_security_insights") or []
print(f"Frontend agentic.result?.ai_security_insights.length: {len(frontend_received_insights)}")

print("\n--- AI Security Findings Surface to Frontend ---")
for idx, item in enumerate(frontend_received_insights, 1):
    print(f"Finding #{idx}: [{item.get('rule_id')}] {item.get('title')} ({item.get('severity')}) at {item.get('file_path') or item.get('file')}:{item.get('line')}")
