"""
AI Code Guardian v3 — Core Specialist Agents Unit Tests
=======================================================
Tests for RepositoryAgent, BusinessAgent, SecurityAgent, ArchitectureAgent,
DependencyAgent, BaseAgent execution, and expanded StateGraph workflow.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.agents import (
    ArchitectureAgent,
    BusinessAgent,
    DependencyAgent,
    RepositoryAgent,
    SecurityAgent,
)
from guardian.orchestrator import (
    AgentRegistry,
    EventBus,
    OrchestratorWorkflow,
    ToolRegistry,
    create_initial_state,
)


def test_repository_agent():
    state = create_initial_state(
        scan_id="scan-repo",
        repository_profile={
            "primary_language": "Python",
            "frameworks": ["FastAPI"],
            "entry_points": ["main.py"],
            "detected_endpoints": ["/api/v1/auth"],
            "security_markers": ["auth_jwt"],
        },
    )

    agent = RepositoryAgent()
    res_state = agent.run(state)

    assert res_state["active_agent"] == "repository"
    assert "repository" in res_state["completed_agents"]

    ctx = res_state["repository_context"]
    assert ctx["languages"] == ["Python"]
    assert ctx["frameworks"] == ["FastAPI"]
    assert ctx["entry_points"] == ["main.py"]
    assert ctx["public_apis"] == ["/api/v1/auth"]


def test_business_agent():
    # NOTE: BusinessAgent no longer *infers* compliance_frameworks from
    # domain (e.g. "fintech" => hardcoded "PCI-DSS") -- that was a
    # fabrication the agent used to invent regardless of what the repo's
    # actual business documents said. It now only classifies domain and
    # criticality from the real BusinessIntentEngine output, and passes
    # compliance_frameworks through unchanged from whatever the caller
    # already knows -- it never guesses frameworks the scan has no
    # evidence for. This test supplies compliance_frameworks explicitly
    # and asserts they pass through untouched.
    state = create_initial_state(
        scan_id="scan-biz",
        business_context={
            "domain": "fintech",
            "criticality": "CRITICAL",
            "compliance_frameworks": ["PCI-DSS"],
        },
    )

    agent = BusinessAgent()
    res_state = agent.run(state)

    assert res_state["active_agent"] == "business"
    assert "business" in res_state["completed_agents"]

    ctx = res_state["business_context"]
    assert ctx["domain"] == "fintech"
    assert ctx["criticality"] == "CRITICAL"
    assert "PCI-DSS" in ctx["compliance_frameworks"]


def test_security_agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        py_file = tmp_path / "app.py"
        py_file.write_text("AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

        state = create_initial_state(
            scan_id="scan-sec",
            repository_profile={"repo_path": str(tmp_path), "total_files": 1},
        )

        agent = SecurityAgent()
        res_state = agent.run(state)

        assert res_state["active_agent"] == "security"
        assert "security" in res_state["completed_agents"]

        findings = res_state["findings"]
        assert len(findings) > 0
        assert findings[0]["rule_id"].startswith("SEC-")

        ctx = res_state["security_context"]
        assert ctx["total_findings"] > 0
        assert len(res_state["evidence"]) > 0


def test_architecture_agent():
    state = create_initial_state(
        scan_id="scan-arch",
        repository_profile={
            "primary_language": "Python",
            "frameworks": ["FastAPI"],
            "detected_endpoints": ["/api/v1/users"],
        },
    )

    agent = ArchitectureAgent()
    res_state = agent.run(state)

    assert res_state["active_agent"] == "architecture"
    assert "architecture" in res_state["completed_agents"]

    ctx = res_state["architecture_context"]
    assert len(ctx["service_boundaries"]) > 0
    assert len(ctx["trust_boundaries"]) > 0


def test_dependency_agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("fastapi\nrequests==2.25.1\n")

        state = create_initial_state(
            scan_id="scan-dep",
            repository_profile={
                "repo_path": str(tmp_path),
                "manifest_files": ["requirements.txt"],
            },
        )

        agent = DependencyAgent()
        res_state = agent.run(state)

        assert res_state["active_agent"] == "dependency"
        assert "dependency" in res_state["completed_agents"]

        ctx = res_state["dependency_context"]
        assert ctx["total_dependencies"] == 2
        assert len(ctx["detected_libraries"]) == 2


def test_full_orchestrator_phase4_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "main.py").write_text("import fastapi\nSECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "requirements.txt").write_text("fastapi\n")

        workflow = OrchestratorWorkflow()

        final_state = workflow.execute(
            scan_id="scan-phase4-full",
            repository_profile={
                "repo_path": str(tmp_path),
                "primary_language": "Python",
                "frameworks": ["FastAPI"],
                "entry_points": ["main.py"],
                "manifest_files": ["requirements.txt"],
            },
            business_context={"domain": "healthcare", "criticality": "CRITICAL"},
            policy_context={"frameworks": ["NIST_800_53"]},
        )

        assert final_state["scan_id"] == "scan-phase4-full"

        # Verify all 5 core specialist agents + planner executed in order
        completed = final_state["completed_agents"]
        expected_agents = ["planner", "repository", "business", "security", "architecture", "dependency"]
        for ag in expected_agents:
            assert ag in completed, f"Agent '{ag}' missing from completed_agents: {completed}"

        # Verify context objects populated
        assert "languages" in final_state["repository_context"]
        assert "domain" in final_state["business_context"]
        assert "total_findings" in final_state["security_context"]
        assert "service_boundaries" in final_state["architecture_context"]
        assert "total_dependencies" in final_state["dependency_context"]

        # Verify traces and metrics recorded for all agents
        traces = final_state["agent_trace"]
        assert len(traces) >= 6
        metrics = final_state["execution_metrics"]
        assert len(metrics["agent_runtime"]) >= 6
