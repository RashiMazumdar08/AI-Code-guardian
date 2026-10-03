import json
import urllib.request
import time
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"

def run_trace():
    print("=== Step 1: Checking deterministic scans ===")
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/v1/scans")
        with urllib.request.urlopen(req) as resp:
            scans = json.loads(resp.read().decode("utf-8"))
            print(f"Found {len(scans)} deterministic scan(s)")
            if not scans:
                print("No deterministic scans found on server. Triggering deterministic scan first...")
                repo_path = "c:/Users/Rashi Mazumdar/Downloads/ai_features-main (2)/ai_features-main"
                req_post = urllib.request.Request(
                    f"{BASE_URL}/api/v1/scans",
                    data=json.dumps({"target_path": repo_path, "scan_mode": "precision"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req_post) as resp_post:
                    scan_data = json.loads(resp_post.read().decode("utf-8"))
                    source_scan_id = scan_data.get("scan_id")
                    print(f"Created deterministic scan: {source_scan_id}")
            else:
                source_scan_id = scans[0].get("scan_id")
                print(f"Using existing scan_id: {source_scan_id}")
    except Exception as e:
        print(f"Error querying scans endpoint: {e}")
        return

    print(f"\n=== Step 2: Triggering ONE Agentic Scan for source_scan_id={source_scan_id} ===")
    start_req = urllib.request.Request(
        f"{BASE_URL}/api/v1/agentic-scan/start",
        data=json.dumps({"scan_id": source_scan_id, "scan_mode": "full_scan"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(start_req) as resp:
        start_res = json.loads(resp.read().decode("utf-8"))
        agentic_scan_id = start_res.get("agentic_scan_id")
        print(f"Agentic scan started! agentic_scan_id={agentic_scan_id}")

    print("\n=== Step 3: Polling status until completion ===")
    for i in range(60):
        time.sleep(2)
        status_req = urllib.request.Request(f"{BASE_URL}/api/v1/agentic-scan/{agentic_scan_id}")
        with urllib.request.urlopen(status_req) as resp:
            status_res = json.loads(resp.read().decode("utf-8"))
            st = status_res.get("status")
            print(f"[{i*2}s] Scan status: {st}")
            if st in ("completed", "failed"):
                print("\n=== Step 4: Full API Result Inspection ===")
                result = status_res.get("result", {})
                bus_analysis = result.get("business_analysis", {})
                bus_results = bus_analysis.get("results", {})
                ai_insights = result.get("ai_business_insights", [])
                
                print(f"result.business_analysis.results.grok_status = {bus_results.get('grok_status') if isinstance(bus_results, dict) else 'N/A'}")
                print(f"result.business_analysis.results.agent_reason = {bus_results.get('agent_reason') if isinstance(bus_results, dict) else 'N/A'}")
                print(f"len(result.business_analysis.ai_business_insights) = {len(bus_analysis.get('ai_business_insights', []))}")
                print(f"len(result.ai_business_insights) = {len(ai_insights)}")
                if ai_insights:
                    print(f"First insight: {json.dumps(ai_insights[0], indent=2)}")
                break

if __name__ == "__main__":
    run_trace()
