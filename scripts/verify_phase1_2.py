"""
Verify Phase 1-2 orchestrator fixes (agents + planner + LangGraph routing).

Run from the repo root:

    python scripts/verify_phase1_2.py

This builds a small THROWAWAY test repo in a temp directory (never touches
your real project files) containing one obvious hardcoded secret and one
SQL injection, then runs the real OrchestratorWorkflow against it and
checks the specific things Phase 1-2 was supposed to fix:

  1. SecurityAgent findings carry real file/line/category (not blank
     defaults from the old wrong attribute names).
  2. BusinessAgent returns a real BusinessIntentEngine result (not the old
     hardcoded fintech/PCI-DSS stub).
  3. DependencyAgent's dependency context is populated (OSV check enabled,
     not silently disabled).
  4. PatchGenerationAgent's suggested fixes are language-appropriate.
  5. scan_mode="security_only" actually skips business / architecture /
     threat_simulation / policy / patch instead of running them anyway.
  6. A repo with zero findings skips patch generation even when patch is
     in the plan.

NOTE: this intentionally does NOT reuse tests/test_orchestrator.py's
test_stategraph_workflow_execution, because that test scans repo_path="."
with no repo_path override -- against this project's own checkout that
means scanning the whole tree including node_modules/.venv, which is slow
enough to look like a hang. This script always points the scan at a tiny
temp directory instead, so it finishes in a few seconds.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from guardian.discovery.file_walker import FileWalker
from guardian.discovery.repo_detector import RepositoryDetector
from guardian.config import GuardianConfig
from guardian.orchestrator.workflow import OrchestratorWorkflow
from guardian.orchestrator.state import create_initial_state

SOURCE_EXTENSIONS = {".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".rs"}

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []  # (check, status, detail)


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((name, PASS if condition else FAIL, detail))
    mark = "✅" if condition else "❌"
    print(f"{mark} {name}" + (f" -- {detail}" if detail and not condition else ""))


def build_profile(repo_dir: Path) -> dict:
    cfg = GuardianConfig()
    walker = FileWalker(cfg)
    discovered = walker.discover(repo_dir, source_extensions=SOURCE_EXTENSIONS)
    profile = RepositoryDetector().detect(repo_dir, discovered.all_files).to_dict()
    profile["repo_path"] = str(repo_dir)
    return profile


def main() -> int:
    vuln_dir = Path(tempfile.mkdtemp(prefix="guardian_verify_vuln_"))
    empty_dir = Path(tempfile.mkdtemp(prefix="guardian_verify_empty_"))
    try:
        (vuln_dir / "app.py").write_text(
            "import os\n\n"
            "AWS_SECRET_KEY = \"AKIAABCDEFGHIJKLMNOP\"\n\n"
            "def get_user(user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = \" + user_id\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        (vuln_dir / "requirements.txt").write_text("requests==2.25.0\nflask==1.1.2\n")
        (empty_dir / "README.md").write_text("# nothing security-sensitive here\n")

        vuln_profile = build_profile(vuln_dir)
        empty_profile = build_profile(empty_dir)

        wf = OrchestratorWorkflow()
        print(f"\nUsing graph engine: {type(wf.compiled_graph).__name__}\n")

        # --- 1 & 2 & 3 & 4: full scan against the vulnerable repo ---
        full = wf.execute(
            scan_id="verify-full",
            repository_profile=vuln_profile,
            business_context={},
            policy_context={},
        )

        findings = full.get("findings", [])
        check("Full scan found both seeded vulnerabilities", len(findings) == 2,
              f"got {len(findings)} findings")
        secret_finding = next((f for f in findings if f.get("rule_id") == "SEC-004"), None)
        sqli_finding = next((f for f in findings if f.get("rule_id") == "SEC-001"), None)
        check(
            "Finding file/line are real (not blank) -- SecurityAgent attribute fix",
            bool(secret_finding and secret_finding.get("file_path") == "app.py" and secret_finding.get("line_number")),
            f"secret finding: {secret_finding}",
        )

        bi = full.get("business_intent_results", {})
        check(
            "BusinessAgent used the real BusinessIntentEngine (status != stub)",
            bi.get("status") == "SUCCESS" and bi.get("total_rules", 0) > 0,
            f"business_intent_results: {bi}",
        )
        check(
            "BusinessAgent domain/criticality no longer hardcoded fintech/PCI-DSS defaults",
            full.get("business_context", {}).get("compliance_frameworks") != ["PCI-DSS", "GDPR", "OWASP_TOP_10"],
            f"business_context: {full.get('business_context')}",
        )

        dep_ctx = full.get("dependency_context", {})
        check(
            "DependencyAgent populated dependency context (OSV path runs, not skipped)",
            dep_ctx.get("total_dependencies") == 2 and len(dep_ctx.get("detected_libraries", [])) == 2,
            f"dependency_context: {dep_ctx}",
        )

        patches = full.get("patches", [])
        check("A patch was generated for each finding", len(patches) == len(findings),
              f"{len(patches)} patches for {len(findings)} findings")
        py_patch = patches[0].get("suggested_replacement", "") if patches else ""
        check(
            "Patch snippet is Python-appropriate for this Python repo",
            ("os.environ" in py_patch) or ("cursor.execute" in py_patch),
            f"suggested_replacement: {py_patch!r}",
        )

        # --- 5: security_only mode skips the optional agents ---
        seconly_state = create_initial_state(
            scan_id="verify-seconly",
            repository_profile=vuln_profile,
            scan_mode="security_only",
        )
        seconly = wf.compiled_graph.invoke(seconly_state, config={"configurable": {"thread_id": "verify-seconly"}})
        completed = seconly.get("completed_agents", [])
        check(
            "security_only mode skips business/architecture/threat_simulation/policy/patch",
            all(a not in completed for a in ("business", "architecture", "threat_simulation", "policy", "patch")),
            f"completed_agents: {completed}",
        )
        check("security_only mode still finds the vulnerabilities", len(seconly.get("findings", [])) == 2,
              f"got {len(seconly.get('findings', []))} findings")

        # --- 6: no findings -> patch generation skipped even though planned ---
        empty = wf.execute(
            scan_id="verify-empty",
            repository_profile=empty_profile,
            business_context={},
            policy_context={},
        )
        check(
            "Zero-finding repo skips patch generation",
            "patch" not in empty.get("completed_agents", []) and empty.get("patches", []) == [],
            f"completed_agents: {empty.get('completed_agents')}",
        )

    finally:
        shutil.rmtree(vuln_dir, ignore_errors=True)
        shutil.rmtree(empty_dir, ignore_errors=True)

    failed = [r for r in results if r[1] == FAIL]
    print("\n" + "=" * 60)
    if failed:
        print(f"RESULT: {len(failed)} check(s) FAILED out of {len(results)}")
        for name, _, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    print(f"RESULT: all {len(results)} checks PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
