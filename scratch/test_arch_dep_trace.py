"""
Trace script for ArchitectureAgent and DependencyAgent execution.
"""
import tempfile
from pathlib import Path
import json

from guardian.orchestrator.workflow import OrchestratorWorkflow
from guardian.orchestrator.state import create_initial_state
from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result, _curated_state

with tempfile.TemporaryDirectory() as tmpdir:
    tmp_path = Path(tmpdir)
    (tmp_path / "app.py").write_text("""
from flask import Flask, request, session, render_template
app = Flask(__name__)

@app.route('/')
def home():
    return "Hello"

@app.route('/profile')
def profile():
    user = session.get("user")
    return render_template("profile.html", user=user)
""")
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\nrequests==2.25.1\n")

    workflow = OrchestratorWorkflow()

    final_state = workflow.execute(
        scan_id="trace-arch-dep-test",
        repository_profile={
            "repo_path": str(tmp_path),
            "primary_language": "Python",
            "frameworks": ["Flask"],
            "entry_points": ["app.py"],
            "detected_endpoints": ["/", "/profile"],
            "manifest_files": ["requirements.txt"],
        }
    )

    completed = final_state.get("completed_agents", [])
    print(f"\n==================== RUNTIME AGENT TRACE ====================")
    print(f"Executed Agents List: {completed}")
    print(f"ArchitectureAgent executed = {'YES' if 'architecture' in completed else 'NO'}")
    print(f"DependencyAgent executed   = {'YES' if 'dependency' in completed else 'NO'}")

    print("\n--- ArchitectureAgent Output ---")
    print(f"State Key: 'architecture_context'")
    print(f"Key Present in LangGraph State: {'architecture_context' in final_state}")
    print("architecture_context Content:", json.dumps(final_state.get("architecture_context", {}), indent=2))
    print(f"ai_architecture_insights in LangGraph State: {'ai_architecture_insights' in final_state}")

    print("\n--- DependencyAgent Output ---")
    print(f"State Key: 'dependency_context'")
    print(f"Key Present in LangGraph State: {'dependency_context' in final_state}")
    print("dependency_context Content:", json.dumps(final_state.get("dependency_context", {}), indent=2))
    dep_findings = [f for f in final_state.get("findings", []) if f.get("category") == "dependency" or (f.get("rule_id") or "").startswith("DEP")]
    print(f"Dependency Findings Appended to 'findings' ({len(dep_findings)}):", json.dumps(dep_findings, indent=2))

    # Test API Serialization
    curated = _curated_state(final_state)
    api_record = {
        "source_scan_id": "base-test-123",
        "status": "completed",
        "scan_mode": "full_scan",
        "started_at": 123456789.0,
        "repository_profile": final_state.get("repository_profile", {})
    }
    api_result = _build_agentic_analysis_result("trace-arch-dep-test", api_record, curated)

    print("\n==================== API RESPONSE MODEL TRACE ====================")
    print("API JSON Field 'architecture_analysis':", json.dumps(api_result.get("architecture_analysis"), indent=2))
    print("Is 'architecture_analysis' present in API JSON = YES")
    print("Is 'ai_architecture_insights' present in API JSON =", "ai_architecture_insights" in api_result)

    print("API JSON Field 'dependency_analysis':", json.dumps(api_result.get("dependency_analysis"), indent=2))
    print("Is 'dependency_analysis' present in API JSON = YES")
    print("===================================================================\n")
