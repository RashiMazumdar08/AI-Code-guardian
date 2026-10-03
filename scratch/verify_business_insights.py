import time
import json
import sys
import uuid
from pathlib import Path

repo_root = Path.cwd()
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from guardian.reasoning.gateway import reset_scan_token_trackers, get_scan_token_tracker
from backend.app.main import app
from fastapi.testclient import TestClient

def main():
    print("=== LIVE AGENTIC SCAN VERIFICATION FOR BUSINESSAGENT ===")
    reset_scan_token_trackers()
    client = TestClient(app)

    scan_id = f"live_scan_{uuid.uuid4().hex[:8]}"

    target_dir = Path.cwd() / "tests" / "fixtures" / "business_order_app"
    scan_payload = {
        "scan_id": scan_id,
        "target_path": str(target_dir),
        "scan_mode": "precision",
        "enable_ai": False,
    }
    resp = client.post("/api/v1/scans", json=scan_payload)
    print(f"[*] Triggered deterministic scan. Status: {resp.status_code}")

    # Step 2: Start Agentic Scan
    start_resp = client.post("/api/v1/agentic-scan/start", json={"scan_id": scan_id, "scan_mode": "full_scan"})
    agentic_run_id = start_resp.json()["scan_id"]
    print(f"[*] Started Agentic Scan. agentic_run_id: {agentic_run_id}")

    # Step 3: Monitor until completed or error
    start_time = time.time()
    for _ in range(600):
        st_resp = client.get(f"/api/v1/agentic-scan/{agentic_run_id}")
        if st_resp.status_code == 200:
            st = st_resp.json()
            status = st.get("status")
            state = st.get("state", {})
            completed_agents = state.get("completed_agents", [])
            print(f"[{round(time.time() - start_time)}s] Scan Status: {status} | Completed Agents: {completed_agents}")
            if status in ("completed", "error"):
                break
        time.sleep(2)

    # Step 4: Inspect results
    final_resp = client.get(f"/api/v1/agentic-scan/{agentic_run_id}")
    final_data = final_resp.json()
    result = final_data.get("result", {})
    biz = result.get("business_analysis", {})
    insights = result.get("ai_business_insights", [])

    print("\n" + "=" * 70)
    print("FINAL AGENTIC SCAN BUSINESS RESULTS")
    print("=" * 70)
    print("Overall Status:", final_data.get("status"))
    print("Business Analysis Status:", biz.get("status"))
    print("Business Analysis Grok Status:", biz.get("grok_status"))
    print("Business Analysis Reason:", biz.get("agent_reason"))
    print("AI Business Insights Count:", len(insights))

    for i, ins in enumerate(insights):
        print(f"\n--- AI Insight {i+1} ---")
        print("  Rule / Policy ID:", ins.get("rule_id") or ins.get("policy_id"))
        print("  Verdict:", ins.get("verdict"))
        print("  Confidence:", ins.get("confidence"))
        print("  Reason:", ins.get("reason"))
        print("  File:", ins.get("file"))
        print("  Line:", ins.get("line"))

    tracker = get_scan_token_tracker(agentic_run_id)
    summary = tracker.get_summary()

    print("\n" + "=" * 70)
    print("TOKEN BUDGET & ADMISSION AUDIT")
    print("=" * 70)
    print(f"TOTAL BUDGET = 6500")
    print(f"TOTAL ACTUAL EXTERNAL LLM TOKENS = {summary['total_spent']}")
    print(f"TOTAL UNUSED = {summary['remaining_budget']}")
    print(f"SECURITY = {summary['agent_spent'].get('security', 0)}")
    print(f"BUSINESS = {summary['agent_spent'].get('business', 0)}")
    print(f"ARCHITECTURE = {summary['agent_spent'].get('architecture', 0)}")
    print(f"THREAT = {summary['agent_spent'].get('threat_simulation', 0)}")
    print("=" * 70)

if __name__ == "__main__":
    main()
