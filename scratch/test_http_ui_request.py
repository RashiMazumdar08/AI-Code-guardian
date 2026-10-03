import requests
import time
import json
import sys
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"

def test_live_http_scan():
    print("1. Triggering deterministic scan via HTTP POST /api/v1/scans...", flush=True)
    docs_dir = Path("data/business_docs")
    docs = [str(p) for p in docs_dir.glob("*.pdf")]
    
    scan_req = {
        "target_path": str(Path.cwd()),
        "scan_mode": "precision",
        "enable_ai": False,
        "requirements": docs if docs else None
    }
    
    r = requests.post(f"{BASE_URL}/api/v1/scans", json=scan_req)
    print(f"HTTP {r.status_code}: {r.text[:200]}", flush=True)
    res = r.json()
    source_scan_id = res.get("scan_id")
    print(f"Adopted source scan ID: {source_scan_id}", flush=True)
    
    print("\n2. Triggering agentic scan via HTTP POST /api/v1/agentic-scan/start...", flush=True)
    agentic_req = {
        "scan_id": source_scan_id,
        "scan_mode": "full_scan"
    }
    
    r2 = requests.post(f"{BASE_URL}/api/v1/agentic-scan/start", json=agentic_req)
    print(f"HTTP {r2.status_code}: {r2.text[:200]}", flush=True)
    agentic_res = r2.json()
    agentic_run_id = agentic_res.get("scan_id")
    print(f"Agentic Run ID: {agentic_run_id}", flush=True)
    
    print("\n3. Polling status until completed...", flush=True)
    for _ in range(30):
        time.sleep(2)
        r3 = requests.get(f"{BASE_URL}/api/v1/agentic-scan/{agentic_run_id}")
        if r3.status_code == 200:
            data = r3.json()
            status = data.get("status")
            print(f"Current status: {status}", flush=True)
            if status in ("completed", "error", "cancelled"):
                result = data.get("result") or {}
                bi = result.get("business_analysis") or {}
                res_obj = bi.get("results") or {}
                print("\n" + "="*80, flush=True)
                print("HTTP AGENTIC SCAN COMPLETED", flush=True)
                print(f"grok_status: {res_obj.get('grok_status')}", flush=True)
                print(f"agent_reason: {res_obj.get('agent_reason')}", flush=True)
                print(f"ai_business_insights count: {len(bi.get('ai_business_insights', []))}", flush=True)
                print("="*80, flush=True)
                break

if __name__ == "__main__":
    test_live_http_scan()
