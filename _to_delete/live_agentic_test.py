import sys, os, time, json, tempfile
sys.path.insert(0, ".")

from guardian.core.pipeline import ScanPipeline
from backend.app.api.v1 import scans as scans_mod
from backend.app.api.v1 import agentic_scan as ag_mod
from guardian.reporting.agentic_html_reporter import render_agentic_report_html
from guardian.reporting import report_view_model as rvm

# --- 1. Build a tiny, deliberately-vulnerable target so the real scan
#        finds exactly one thing and the agent graph has minimal work,
#        keeping this live LLM run fast. ---
tmp_dir = tempfile.mkdtemp(prefix="acg_live_test_")
with open(os.path.join(tmp_dir, "payment.py"), "w") as f:
    f.write(
        "import os\n"
        "DB_PASSWORD = \"hunter2_super_secret\"\n\n"
        "def process_refund(user_id, amount):\n"
        "    # no approval check for large refunds\n"
        "    return True\n"
    )

t0 = time.time()
pipeline = ScanPipeline()
report = pipeline.scan(tmp_dir)
scan = report.get("scan", {}) or {}
print(f"[t+{time.time()-t0:.1f}s] deterministic scan done: total_findings={scan.get('total_findings')} by_severity={scan.get('by_severity')}")

det_scan_id = "live_det_scan_1"
scans_mod._SCANS_STORE[det_scan_id] = report

# --- 2. Seed the agentic run record exactly as start_agentic_scan() does,
#        then call the REAL synchronous worker function directly (same
#        code backend/app/api/v1/agentic_scan.py's background thread
#        calls) -- real LangGraph graph, real agents, real LLM calls. ---
agentic_scan_id = "live_agentic_scan_1"
ag_mod._SCANS[agentic_scan_id] = {
    "status": "queued", "log": [], "queues": [], "state": {}, "result": None,
    "error": None, "source_scan_id": det_scan_id, "scan_mode": "full_scan",
    "started_at": time.time(), "deterministic_baseline": None,
    "agentic_summary": None, "cancel_requested": False,
}

print(f"[t+{time.time()-t0:.1f}s] starting REAL agentic workflow (live LLM calls)...")
ag_mod._run_agentic_scan(agentic_scan_id, det_scan_id, "full_scan")
print(f"[t+{time.time()-t0:.1f}s] agentic workflow finished")

record = ag_mod._SCANS[agentic_scan_id]
print("status:", record["status"])
print("error:", record.get("error"))
print("completed_agents:", record["state"].get("completed_agents"))
print("agentic_summary:", json.dumps(record.get("agentic_summary"), default=str))

if record["status"] != "completed":
    print("LIVE RUN DID NOT COMPLETE -- stopping before report render.")
    sys.exit(1)

curated_state = record["state"]

# --- 3. Render both reports from 100% real, live agentic output. ---
html_agentic = render_agentic_report_html(curated_state, None, det_scan_id)
html_unified = render_agentic_report_html(curated_state, report, det_scan_id)

with open("/tmp/live_agentic_report.html", "w") as f:
    f.write(html_agentic)
with open("/tmp/live_unified_report.html", "w") as f:
    f.write(html_unified)
with open("/tmp/live_curated_state.json", "w") as f:
    json.dump(curated_state, f, indent=2, default=str)

print("agentic report len:", len(html_agentic))
print("unified report len:", len(html_unified))

# --- 4. Real assertions against LIVE agent output (not synthetic). ---
assert "guardian_github_repos" not in html_unified
assert tmp_dir not in html_unified, "raw temp scan directory leaked into the report"
assert "Deterministic Security Findings" not in html_agentic
assert "Deterministic Security Findings" in html_unified

patches = curated_state.get("patches") or []
validation_results = curated_state.get("validation_results") or []
print("real patches:", len(patches), "real validation_results:", len(validation_results))
groups = rvm.group_patches_by_status(patches, validation_results)
for k, v in groups.items():
    print(" ", k, len(v))

attack_paths = curated_state.get("attack_paths") or []
print("real attack_paths:", len(attack_paths))

business_violations = curated_state.get("business_violations") or []
print("real business_violations:", len(business_violations))
for v in business_violations:
    print("   -", v.get("rule_id"), v.get("status"), "|", (v.get("why") or v.get("what") or "")[:100])

risk_scores = curated_state.get("risk_scores")
print("real risk_scores:", risk_scores)

print("ALL LIVE-RUN ASSERTIONS PASSED")
print(f"[t+{time.time()-t0:.1f}s] total wall time")
