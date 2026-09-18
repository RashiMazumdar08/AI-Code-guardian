import sys
sys.path.insert(0, ".")
from starlette.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

# A structurally-real curated-state payload -- same shape a completed run's
# sessionStorage cache sends (see frontend's handleDownloadAgenticReport /
# useAgenticScan.ts), just without live LLM content.
agentic_payload = {
    "scan_id": "agentic_http_test",
    "source_scan_id": "det_http_test",
    "completed_agents": ["planner", "repository"],
    "findings": [
        {"finding_id": "F-1", "rule_id": "SEC-004", "category": "Hardcoded Secret", "severity": "Critical", "file": "payment.py", "line": 2},
    ],
    "business_violations": [],
    "attack_paths": [],
    "patches": [],
    "validation_results": [],
    "risk_scores": {},
    "correlated_findings": {},
}
deterministic_payload = {
    "target": "tmp_target",
    "repository": {"root": ""},
    "scan": {
        "total_findings": 1,
        "by_severity": {"Critical": 1},
        "findings": agentic_payload["findings"],
    },
}

# --- Agentic-only download ---
r1 = client.post("/api/v1/reports/agentic-download", json={
    "agentic": agentic_payload, "deterministic_scan_id": "det_http_test",
})
print("agentic-only status:", r1.status_code)
print("content-type:", r1.headers.get("content-type"))
print("content-disposition:", r1.headers.get("content-disposition"))
assert r1.status_code == 200
assert "text/html" in r1.headers.get("content-type", "")
assert "agentic_report" in r1.headers.get("content-disposition", "")
assert "Deterministic Security Findings" not in r1.text
assert len(r1.text) > 1000

# --- Unified download ---
r2 = client.post("/api/v1/reports/agentic-download", json={
    "agentic": agentic_payload, "deterministic": deterministic_payload,
    "deterministic_scan_id": "det_http_test",
})
print("unified status:", r2.status_code)
print("content-disposition:", r2.headers.get("content-disposition"))
assert r2.status_code == 200
assert "unified_report" in r2.headers.get("content-disposition", "")
assert "Deterministic Security Findings" in r2.text
assert "SEC-004" in r2.text

with open("/tmp/http_agentic_response.html", "w") as f:
    f.write(r1.text)
with open("/tmp/http_unified_response.html", "w") as f:
    f.write(r2.text)

print("ALL HTTP ENDPOINT ASSERTIONS PASSED (real FastAPI request/response cycle)")
