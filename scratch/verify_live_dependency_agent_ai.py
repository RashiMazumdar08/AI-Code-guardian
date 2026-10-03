"""
Controlled Live Test Verification Script for AI-Enhanced Dependency Agent
"""
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardian.agents.dependency import DependencyAgent
from guardian.orchestrator.state import create_initial_state
from backend.app.api.v1.agentic_scan import _STATE_KEYS, _curated_state, _build_agentic_analysis_result


def main():
    print("=== STARTING CONTROLLED LIVE DEPENDENCY AGENT VERIFICATION ===")
    
    with TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        manifest_file = tmp_dir / "requirements.txt"
        manifest_file.write_text("urllib3==1.24.1\nrequests==2.25.1\n")
        
        app_file = tmp_dir / "app.py"
        app_file.write_text("""
import urllib3
import requests

def make_request(url):
    http = urllib3.PoolManager()
    return http.request('GET', url)
""")

        state = create_initial_state(
            scan_id="scan-live-dep-test",
            repository_profile={
                "repo_path": str(tmp_dir),
                "manifest_files": ["requirements.txt"],
            }
        )

        # Seeding state with deterministic findings
        state["findings"] = [
            {
                "finding_id": "dep-1",
                "rule_id": "CVE-2021-33503",
                "title": "Vulnerable Dependency: urllib3 (CVE-2021-33503)",
                "severity": "HIGH",
                "category": "dependency",
                "file_path": "requirements.txt",
                "package": "urllib3",
                "description": "ReDoS vulnerability in urllib3 header parser."
            }
        ]

        agent = DependencyAgent()
        new_state = agent.run(state)

        dep_ctx = new_state.get("dependency_context", {})
        ai_insights = new_state.get("ai_dependency_insights", [])

        print("\n--- DETERMINISTIC FINDINGS & CONTEXT ---")
        print(f"Total Packages: {dep_ctx.get('total_dependencies')}")
        print(f"Detected Libraries: {[lib['name'] for lib in dep_ctx.get('detected_libraries', [])]}")
        print(f"Vulnerable Findings Count: {dep_ctx.get('vulnerable_dependencies_count')}")
        print(f"Grok AI Status: {dep_ctx.get('grok_status')}")
        print(f"Agent Reason: {dep_ctx.get('agent_reason')}")

        print("\n--- AI DEPENDENCY INSIGHTS ---")
        print(f"AI Insight Count: {len(ai_insights)}")
        for idx, insight in enumerate(ai_insights, start=1):
            print(f"\n[Insight #{idx}]")
            print(f"  ID: {insight.get('id')}")
            print(f"  Package: {insight.get('package')}")
            print(f"  Vulnerability ID: {insight.get('vulnerability_id')}")
            print(f"  Severity: {insight.get('severity')}")
            print(f"  Relevance: {insight.get('relevance')}")
            print(f"  Usage Context: {insight.get('usage_context')}")
            print(f"  Analysis: {insight.get('analysis')}")
            print(f"  Remediation: {insight.get('remediation')}")

        curated = _curated_state(new_state)
        record = {"source_scan_id": "base-live-123", "status": "COMPLETED", "scan_mode": "full_scan"}
        result_envelope = _build_agentic_analysis_result("scan-live-dep-test", record, curated)

        print("\n--- API RESULT ENVELOPE VERIFICATION ---")
        assert "ai_dependency_insights" in result_envelope
        assert "ai_dependency_insights" in result_envelope["dependency_analysis"]
        print("[OK] API Envelope verification passed successfully!")
        print("=== CONTROLLED LIVE DEPENDENCY AGENT VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    main()
