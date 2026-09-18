"""
AI Code Guardian v3 — Phase 6 Unit Tests
========================================
Tests for PatchGenerationAgent, PatchProposal, GroundingEngine, ValidationAgent,
GitDiffGenerator, PatchVerificationService, and full Phase 6 workflow.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.agents import (
    PatchGenerationAgent,
    PatchProposal,
    PatchVerificationService,
    ValidationAgent,
)
from guardian.orchestrator import (
    OrchestratorWorkflow,
    create_initial_state,
)
from guardian.reasoning.grounding import GitDiffGenerator, GroundingEngine


def test_patch_proposal_model():
    proposal = PatchProposal(
        patch_id="p-101",
        finding_id="f-1",
        affected_file="auth.py",
        affected_lines="10-12",
        original_snippet="key = '12345'",
        suggested_replacement="key = os.environ.get('KEY')",
        evidence_ids=["ev-1"],
    )
    p_dict = proposal.to_dict()
    assert p_dict["patch_id"] == "p-101"
    assert p_dict["evidence_ids"] == ["ev-1"]
    assert p_dict["validation_status"] == "PENDING"


def test_git_diff_generator():
    gen = GitDiffGenerator()
    orig = "def login():\n    return False\n"
    repl = "def login():\n    return True\n"

    diff = gen.generate_unified_diff("auth.py", orig, repl)

    assert "--- a/auth.py" in diff
    assert "+++ b/auth.py" in diff
    assert "-    return False" in diff
    assert "+    return True" in diff


def test_grounding_engine():
    engine = GroundingEngine()
    patch = {
        "patch_id": "p-1",
        "finding_id": "f-1",
        "affected_file": "app.py",
        "evidence_ids": ["ev-1"],
    }
    findings = [{"finding_id": "f-1", "evidence_id": "ev-1"}]
    evidence = [{"evidence_id": "ev-1", "finding_id": "f-1"}]

    res = engine.verify_patch(patch, findings, evidence)
    assert res["passed"] is True

    # Test hallucinated finding rejection
    patch_fake = {"finding_id": "f-fake", "evidence_ids": ["ev-fake"]}
    res_fake = engine.verify_patch(patch_fake, findings, evidence)
    assert res_fake["passed"] is False
    assert len(res_fake["reasons"]) > 0


def test_mechanical_verification_service():
    service = PatchVerificationService()
    orig_finding = {"finding_id": "f-1", "rule_id": "SEC-004"}
    patched_code = "import os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY')"

    res = service.verify_remediation(orig_finding, patched_code, language="python")
    assert res["syntax_valid"] is True
    assert res["resolved"] is True

    # Test invalid syntax
    invalid_code = "def broken_syntax(:\n"
    res_invalid = service.verify_remediation(orig_finding, invalid_code, language="python")
    assert res_invalid["syntax_valid"] is False
    assert res_invalid["resolved"] is False


def test_patch_generation_agent():
    state = create_initial_state(
        scan_id="scan-patch-gen",
        findings=[{
            "finding_id": "f-1",
            "rule_id": "SEC-004",
            "file_path": "config.py",
            "line_number": 5,
            "snippet": "SECRET = 'AKIAIOSFODNN7EXAMPLE'",
            "evidence_id": "ev-1",
        }],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
        business_context={"criticality": "CRITICAL"},
    )

    agent = PatchGenerationAgent()
    res = agent.run(state)

    assert res["active_agent"] == "patch"
    assert "patch" in res["completed_agents"]

    patches = res["patches"]
    assert len(patches) == 1
    assert patches[0]["finding_id"] == "f-1"
    assert "git_diff" in res
    assert "--- a/config.py" in res["git_diff"]
    assert "developer_explanation" in res


def test_validation_agent():
    state = create_initial_state(
        scan_id="scan-val",
        findings=[{
            "finding_id": "f-1",
            "rule_id": "SEC-004",
            "file_path": "config.py",
            "evidence_id": "ev-1",
        }],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
        repository_profile={"primary_language": "python"},
    )

    state["patches"] = [{
        "patch_id": "p-1",
        "finding_id": "f-1",
        "affected_file": "config.py",
        "original_snippet": "SECRET = '123'",
        "suggested_replacement": "import os\nSECRET = os.environ.get('SECRET')",
        "evidence_ids": ["ev-1"],
        "confidence": 0.90,
    }]

    agent = ValidationAgent()
    res = agent.run(state)

    assert res["active_agent"] == "validation"
    assert "validation" in res["completed_agents"]

    val_res = res["validation_results"]
    assert len(val_res) == 1
    assert val_res[0]["status"] == "PASSED"
    assert res["validation_report"]["passed_count"] == 1


def test_full_phase6_langgraph_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "main.py").write_text("import fastapi\nAWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "requirements.txt").write_text("fastapi\nrequests==2.25.1\n")

        workflow = OrchestratorWorkflow()

        final_state = workflow.execute(
            scan_id="scan-phase6-full",
            repository_profile={
                "repo_path": str(tmp_path),
                "primary_language": "Python",
                "frameworks": ["FastAPI"],
                "entry_points": ["main.py"],
                "manifest_files": ["requirements.txt"],
            },
            business_context={"domain": "fintech", "criticality": "CRITICAL"},
            policy_context={"frameworks": ["OWASP_TOP_10", "NIST_800_53"]},
        )

        assert final_state["scan_id"] == "scan-phase6-full"

        completed = final_state["completed_agents"]
        expected_agents = [
            "planner", "repository", "business", "security",
            "architecture", "dependency", "threat_simulation", "policy",
            "risk_fusion", "patch", "validation"
        ]
        for ag in expected_agents:
            assert ag in completed, f"Agent '{ag}' missing from completed_agents: {completed}"

        assert final_state["active_agent"] == "validation"

        # Verify remediation patch artifacts exist in state
        assert len(final_state["patches"]) > 0
        assert "git_diff" in final_state
        assert "developer_explanation" in final_state
        assert final_state["validation_report"]["passed_count"] >= 1
