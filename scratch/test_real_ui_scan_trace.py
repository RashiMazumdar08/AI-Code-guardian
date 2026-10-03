import sys
import os
import json
import logging
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))
logging.basicConfig(level=logging.INFO)

from guardian.core.pipeline import ScanPipeline
from backend.app.api.v1.scans import _SCANS_STORE
from backend.app.api.v1.agentic_scan import _run_agentic_scan, _SCANS
from guardian.intent.ingestion.document_loader import DocumentLoader

def run_ui_equivalent_trace():
    print("Step 1: Running deterministic ScanPipeline on current directory...")
    pipeline = ScanPipeline()
    docs = [str(p) for p in Path("data/business_docs").glob("*.pdf")]
    
    result = pipeline.scan(
        repo_root=str(Path.cwd()),
        business_requirements=docs if docs else None
    )
    
    source_scan_id = "scan_test_ui_001"
    res_dict = result
    res_dict["scan_mode"] = "precision"
    res_dict["target"] = str(Path.cwd())
    _SCANS_STORE[source_scan_id] = res_dict
    
    print(f"Deterministic scan stored with id '{source_scan_id}'. Total findings: {len(result.get('scan', {}).get('findings', []))}")
    
    print("\nStep 2: Triggering Agentic Scan (UI path)...")
    agentic_scan_id = "agentic_test_ui_001"
    _SCANS[agentic_scan_id] = {
        "status": "queued",
        "log": [],
        "queues": [],
        "state": {},
        "result": None,
        "error": None,
        "source_scan_id": source_scan_id,
        "scan_mode": "full_scan",
        "started_at": 1000.0,
        "deterministic_baseline": None,
        "agentic_summary": None,
        "repository_profile": None,
        "cancel_requested": False,
    }

    _run_agentic_scan(agentic_scan_id, source_scan_id, "full_scan")

    record = _SCANS[agentic_scan_id]
    print("\n" + "="*80)
    print("AGENTIC SCAN RESULT SUMMARY")
    print(f"Status: {record.get('status')}")
    print(f"Error: {record.get('error')}")
    
    res = record.get("result") or {}
    bi = res.get("business_analysis") or {}
    print(f"Business Intent Results grok_status: {bi.get('results', {}).get('grok_status')}")
    print(f"Business Intent agent_reason: {bi.get('results', {}).get('agent_reason')}")
    print(f"AI Business Insights Count: {len(bi.get('ai_business_insights', []))}")
    print("="*80)

if __name__ == "__main__":
    run_ui_equivalent_trace()
