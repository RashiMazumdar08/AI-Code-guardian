"""
Live End-to-End Agentic Scan Verification Script
===============================================
Executes a completely new Agentic Scan through the official FastAPI backend API routes.
Captures telemetry, [TOKEN ADMISSION] logs, and reports exact token consumption per agent.
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from pathlib import Path

# Configure root logger to capture [TOKEN ADMISSION] logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("live_verification")

# Ensure project root is in sys.path
repo_root = Path.cwd()
sys.path.insert(0, str(repo_root))

from guardian.reasoning.gateway import (
    reset_scan_token_trackers,
    get_scan_token_tracker,
    format_scan_token_report,
)
from backend.app.main import app
from fastapi.testclient import TestClient


class TokenAdmissionHandler(logging.Handler):
    """Custom logging handler to record [TOKEN ADMISSION] log messages during the live scan."""

    def __init__(self):
        super().__init__()
        self.records: list[str] = []

    def emit(self, record):
        msg = self.format(record)
        if "[TOKEN ADMISSION]" in msg:
            self.records.append(msg)


def main():
    print("=" * 70)
    print("STARTING LIVE END-TO-END AGENTIC SCAN VERIFICATION")
    print("=" * 70)

    # 1. Reset token trackers to ensure clean initial state
    reset_scan_token_trackers()

    # Attach custom log handler to capture token telemetry
    log_handler = TokenAdmissionHandler()
    logging.getLogger().addHandler(log_handler)
    logging.getLogger("guardian").addHandler(log_handler)
    logging.getLogger("guardian.reasoning.gateway").addHandler(log_handler)

    # 2. Generate a completely NEW scan ID
    scan_id = f"live_agentic_scan_{uuid.uuid4().hex[:8]}"
    print(f"[*] Generated fresh scan_id: {scan_id}")

    # 3. Use FastAPI TestClient to execute actual backend API endpoints
    client = TestClient(app)

    # Step A: Trigger deterministic scan via POST /api/v1/scans
    print(f"[*] Step 1: Triggering deterministic scan via POST /api/v1/scans...")
    scan_payload = {
        "scan_id": scan_id,
        "target_path": str(repo_root),
        "scan_mode": "precision",
        "enable_ai": False,
    }
    resp = client.post("/api/v1/scans", json=scan_payload)
    if resp.status_code != 200:
        print(f"[!] Error triggering deterministic scan: {resp.status_code} - {resp.text}")
        sys.exit(1)

    scan_res = resp.json()
    print(f"[+] Deterministic scan completed. Total findings adopted: {scan_res.get('total_findings', 0)}")

    # Step B: Trigger Agentic Scan via POST /api/v1/agentic-scan/start
    print(f"[*] Step 2: Triggering Agentic Scan via POST /api/v1/agentic-scan/start...")
    agentic_payload = {
        "scan_id": scan_id,
        "scan_mode": "full_scan",
    }
    agentic_resp = client.post("/api/v1/agentic-scan/start", json=agentic_payload)
    if agentic_resp.status_code != 200:
        print(f"[!] Error starting agentic scan: {agentic_resp.status_code} - {agentic_resp.text}")
        sys.exit(1)

    start_data = agentic_resp.json()
    agentic_run_id = start_data["scan_id"]
    print(f"[+] Agentic scan started. agentic_run_id: {agentic_run_id}")

    # Wait for scan to complete background processing
    print(f"[*] Step 3: Monitoring agentic scan execution state for {agentic_run_id}...")

    # Wait up to 300 seconds for background supersteps to complete
    import time
    run_status = "queued"
    for i in range(300):
        status_resp = client.get(f"/api/v1/agentic-scan/{agentic_run_id}")
        if status_resp.status_code == 200:
            st = status_resp.json()
            run_status = st.get("status")
            if run_status in ("completed", "error"):
                break
        time.sleep(1)

    print(f"[+] Final Agentic Scan Status: {run_status}")

    # Step C: Telemetry Analysis
    print("\n" + "=" * 70)
    print("CAPTURED [TOKEN ADMISSION] TELEMETRY LOGS")
    print("=" * 70)

    for rec in log_handler.records:
        # Sanitize any accidental credentials just in case
        clean_rec = rec
        for secret_var in ["GEMINI_API_KEY", "NVIDIA_API_KEY", "XAI_API_KEY"]:
            val = os.getenv(secret_var)
            if val and len(val) > 5:
                clean_rec = clean_rec.replace(val, "<MASKED_KEY>")
        print(clean_rec)

    # Step D: Retrieve Token Tracker Summary
    tracker = get_scan_token_tracker(agentic_run_id)
    summary = tracker.get_summary()

    print("\n" + "=" * 70)
    print("FINAL SCAN TOKEN SUMMARY REPORT")
    print("=" * 70)
    report = format_scan_token_report(agentic_run_id)
    print(report)

    # Step E: Breakdown Verification Requirements
    print("\n" + "=" * 70)
    print("AGENT-BY-AGENT ADMISSION & TOKEN CONSUMPTION BREAKDOWN")
    print("=" * 70)

    agent_spent = summary["agent_spent"]
    agent_caps = summary["agent_caps"]

    for agent_name in ["security", "business", "architecture", "threat_simulation", "patch", "validation"]:
        spent = agent_spent.get(agent_name, 0)
        cap = agent_caps.get(agent_name, 0)
        status = "EXECUTED" if spent > 0 else "SKIPPED"
        print(f"Agent: {agent_name:<18} | Status: {status:<10} | Spent: {spent:<5} tokens | Cap: {cap} tokens")

    print("\n" + "=" * 70)
    print("REQUIRED AUDIT VERIFICATION METRICS")
    print("=" * 70)
    print(f"TOTAL BUDGET = 6500")
    print(f"TOTAL ACTUAL EXTERNAL LLM TOKENS = {summary['total_spent']}")
    print(f"TOTAL UNUSED = {summary['remaining_budget']}")
    print(f"SECURITY = {agent_spent.get('security', 0)}")
    print(f"BUSINESS = {agent_spent.get('business', 0)}")
    print(f"ARCHITECTURE = {agent_spent.get('architecture', 0)}")
    print(f"THREAT = {agent_spent.get('threat_simulation', 0)}")
    print(f"PATCH = {agent_spent.get('patch', 0)}")
    print(f"VALIDATION = {agent_spent.get('validation', 0)}")
    print("=" * 70)


if __name__ == "__main__":
    main()
