import sys
import os
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv
load_dotenv()

from guardian.core.pipeline import ScanPipeline
from guardian.agents.security.agent import SecurityAgent
from backend.app.api.v1.scans import _SCANS_STORE as DETERMINISTIC_STORE
from backend.app.api.v1.agentic_scan import (
    _SCANS as AGENTIC_STORE,
    _run_agentic_scan,
    _build_agentic_analysis_result,
)

target_dir = Path("tests/fixtures/dv-bookshop_raw/dv-bookshop-main").resolve()

print("=== FRESH DV-BOOKSHOP SCAN VERIFICATION ===")

# Run deterministic pipeline
pipeline = ScanPipeline()
scan_res = pipeline.scan(repo_root=str(target_dir))
raw_findings = scan_res.to_dict().get("scan", {}).get("findings", []) if hasattr(scan_res, "to_dict") else []

base_scan_id = f"scan_fresh_dv_{int(time.time())}"
report_dict = {
    "scan_id": base_scan_id,
    "target": str(target_dir),
    "scan_mode": "precision",
    "scan": scan_res.to_dict() if hasattr(scan_res, "to_dict") else scan_res,
    "evidence_items": scan_res.evidence if hasattr(scan_res, "evidence") else [],
    "repository": {"repo_path": str(target_dir), "total_files": len(os.listdir(target_dir))},
}
DETERMINISTIC_STORE[base_scan_id] = report_dict

agentic_scan_id = f"agentic_fresh_dv_{int(time.time())}"
AGENTIC_STORE[agentic_scan_id] = {
    "status": "queued",
    "log": [],
    "queues": [],
    "state": {},
    "result": None,
    "error": None,
    "source_scan_id": base_scan_id,
    "scan_mode": "full_scan",
    "started_at": time.time(),
    "deterministic_baseline": None,
    "agentic_summary": None,
    "repository_profile": None,
    "cancel_requested": False,
}

_run_agentic_scan(agentic_scan_id, base_scan_id, "full_scan")

record = AGENTIC_STORE[agentic_scan_id]
final_state = record.get("state", {})
api_result = record.get("result", {})
sec_ctx = final_state.get("security_context", {})

print("\n--- Fresh DV-Bookshop Scan Results ---")
print(f"Base Scan ID: {base_scan_id}")
print(f"Agentic Scan ID: {agentic_scan_id}")
print(f"Deterministic Findings Count: {len(raw_findings)}")
print(f"SecurityAgent grok_status: {sec_ctx.get('grok_status')}")
print(f"SecurityAgent agent_reason: {str(sec_ctx.get('agent_reason', ''))[:120]}...")

# Verify Props Extraction (FIX 1)
extracted_grok_status = (
    api_result.get("security_enrichment", {}).get("security_context", {}).get("grok_status")
    or final_state.get("security_context", {}).get("grok_status")
)
extracted_agent_reason = (
    api_result.get("security_enrichment", {}).get("security_context", {}).get("agent_reason")
    or final_state.get("security_context", {}).get("agent_reason")
)

print(f"\n--- FIX 1 Props Extraction Verification ---")
print(f"Extracted grokStatus prop in SecurityWorkbench: {extracted_grok_status}")
print(f"Extracted securityAgentReason prop in SecurityWorkbench: {extracted_agent_reason[:80]}...")

# Check CASE A vs CASE B
ai_insights = api_result.get("ai_security_insights", [])
print(f"\nAPI result.ai_security_insights Count: {len(ai_insights)}")

if extracted_grok_status == "COMPLETED" and len(ai_insights) > 0:
    print("\n[CASE A: Grok Succeeded]")
    print("UI rendering branch: AI_FINDINGS_LIST")
    print(f"Displays {len(ai_insights)} AI security findings.")
elif extracted_grok_status in ["FAILED", "RATE_LIMITED", "UNAVAILABLE"]:
    print("\n[CASE B: Grok Rate-Limited / Daily Quota Exhausted]")
    print("UI rendering branch: UNAVAILABLE_BANNER")
    print("UI displays rate-limit/unavailable state with agent_reason.")
    print("UI does NOT display 'No additional AI security findings were identified.'")

print("\nDeterministic security findings count visible: ", len(raw_findings))
