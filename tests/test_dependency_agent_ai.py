"""
AI Code Guardian v3 — Dependency Agent AI Analysis Unit Tests
==============================================================
Tests for Groq AI-enhanced DependencyAgent reasoning, gating, budget enforcement,
grounding guarantees, resilience, stable IDs, API exposure, and frontend state integrity.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from backend.app.api.v1.agentic_scan import (
    _STATE_KEYS,
    _build_agentic_analysis_result,
    _curated_state,
)
from guardian.agents.dependency import DependencyAgent
from guardian.orchestrator.state import create_initial_state, merge_list
from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest, ScanTokenTracker, reset_scan_token_trackers


@pytest.fixture(autouse=True)
def _reset_trackers():
    reset_scan_token_trackers()


# 1. Deterministic dependency results remain unchanged
def test_1_deterministic_dependency_results_remain_unchanged(tmp_path):
    fixture_dir = tmp_path / "dep_repo_1"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("requests==2.25.1\n")

    state = create_initial_state(
        scan_id="scan-dep-1",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    new_state = agent.run(state)

    dep_ctx = new_state.get("dependency_context", {})
    assert dep_ctx.get("total_dependencies") == 1
    assert dep_ctx.get("detected_libraries")[0]["name"] == "requests"
    assert dep_ctx.get("detected_libraries")[0]["version"] == "2.25.1"


# 2 & 5. Vulnerable dependency (HIGH/CRITICAL) is eligible and invokes Groq
def test_2_and_5_high_critical_vulnerable_dependency_invokes_groq(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_2"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("urllib3==1.24.1\n")
    (fixture_dir / "app.py").write_text("import urllib3\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    captured_requests = []

    fake_response = json.dumps({
        "summary": "High risk vulnerability in urllib3",
        "findings": [{
            "evidence_ids": ["E1"],
            "package": "urllib3",
            "version": "1.24.1",
            "vulnerability_id": "CVE-2021-33503",
            "analysis": "urllib3 ReDoS vulnerability allows remote Denial of Service.",
            "usage_context": "app.py:1 -> import urllib3",
            "impact": "Application process crash via ReDoS payload.",
            "relevance": "RELEVANT",
            "remediation": "Upgrade urllib3 to >= 1.26.5",
            "category": "dependency_insight",
            "severity": "High",
            "confidence": 0.9,
            "reason": "CRLF and ReDoS vulnerability in urllib3 header parser",
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.schemas import parse_dependency_reasoning_response
            parsed = parse_dependency_reasoning_response(fake_response, task="dependency_reasoning", model="groq-nemotron")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-2",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    # Inject a high severity deterministic finding
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "CVE-2021-33503",
        "title": "Vulnerable Dependency: urllib3 (CVE-2021-33503)",
        "severity": "HIGH",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "urllib3"
    }]

    new_state = agent.run(state)

    assert len(captured_requests) == 1
    req = captured_requests[0]
    assert req.agent == "dependency"
    assert "urllib3" in req.evidence_block

    assert new_state["dependency_context"]["grok_status"] == "COMPLETED"
    assert "ai_dependency_insights" in new_state
    assert len(new_state["ai_dependency_insights"]) == 1
    assert new_state["ai_dependency_insights"][0]["relevance"] == "RELEVANT"


# 3. Non-vulnerable dependency does not invoke LLM
def test_3_non_vulnerable_dependency_does_not_invoke_llm(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_3"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("clean-package==1.0.0\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    called = []

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            called.append(req)
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(available=False, error="Should not be called")

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-3",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    new_state = agent.run(state)

    assert len(called) == 0
    assert new_state["dependency_context"]["grok_status"] == "SKIPPED"


# 4. LOW/INFO does not unnecessarily invoke LLM
def test_4_low_info_finding_does_not_invoke_llm(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_4"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("some-pkg==1.0.0\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    called = []

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            called.append(req)
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(available=False, error="Should not be called")

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-4",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    # Inject LOW severity finding
    agent = DependencyAgent()
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "DEP-001",
        "title": "Unpinned package: some-pkg",
        "severity": "LOW",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "some-pkg"
    }]

    new_state = agent.run(state)

    assert len(called) == 0
    assert new_state["dependency_context"]["grok_status"] == "SKIPPED"


# 6 & 7. Relevant evidence passed & entire repo not sent unnecessarily
def test_6_and_7_relevant_evidence_passed_without_sending_entire_repo(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_6"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("vulnerable-lib==2.0.0\n")
    # Giant file that should NOT be sent directly in full
    (fixture_dir / "app.py").write_text("import vulnerable_lib\n" + "# extra code\n" * 1000)

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    captured_requests = []

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.schemas import parse_dependency_reasoning_response
            resp = parse_dependency_reasoning_response(
                json.dumps({
                    "summary": "Summary",
                    "findings": [{
                        "evidence_ids": ["E1"],
                        "package": "vulnerable-lib",
                        "vulnerability_id": "CVE-2022-9999",
                        "analysis": "Analysis",
                        "relevance": "RELEVANT"
                    }]
                }), task="dependency_reasoning"
            )
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=resp, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-6",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "CVE-2022-9999",
        "title": "Vulnerable Dependency: vulnerable-lib (CVE-2022-9999)",
        "severity": "CRITICAL",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "vulnerable-lib"
    }]

    new_state = agent.run(state)

    assert len(captured_requests) == 1
    req = captured_requests[0]
    # Verify evidence block contains package, severity, and snippet line, NOT the whole 1000 line file
    assert "vulnerable-lib" in req.evidence_block
    assert "CVE-2022-9999" in req.evidence_block
    assert len(req.evidence_block) < 2000


# 8. LLM cannot override CVE/severity
def test_8_llm_cannot_override_cve_or_severity(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_8"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("target-pkg==1.0.0\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    fake_response = json.dumps({
        "summary": "Summary",
        "findings": [{
            "evidence_ids": ["E1"],
            "package": "target-pkg",
            "version": "1.0.0",
            "vulnerability_id": "FABRICATED-CVE-9999",  # LLM tries to invent CVE ID
            "severity": "Low",  # LLM tries to downgrade CRITICAL to Low
            "analysis": "Analysis text",
            "relevance": "RELEVANT",
            "remediation": "Remediation text"
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            from guardian.reasoning.schemas import parse_dependency_reasoning_response
            parsed = parse_dependency_reasoning_response(fake_response, task="dependency_reasoning")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-8",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "CVE-2023-[#REAL]",
        "title": "Vulnerable Dependency: target-pkg (CVE-2023-[#REAL])",
        "severity": "CRITICAL",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "target-pkg"
    }]

    new_state = agent.run(state)

    assert "ai_dependency_insights" in new_state
    insight = new_state["ai_dependency_insights"][0]
    # Enforced deterministic grounding
    assert insight["vulnerability_id"] == "CVE-2023-[#REAL]"
    assert insight["severity"] == "CRITICAL"


# 9. INSUFFICIENT_EVIDENCE is returned when usage evidence is absent
def test_9_insufficient_evidence_when_code_usage_absent(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_9"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("unused-vulnerable-lib==1.0.0\n")
    (fixture_dir / "app.py").write_text("print('no imports here')\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    fake_response = json.dumps({
        "summary": "Summary",
        "findings": [{
            "evidence_ids": ["E1"],
            "package": "unused-vulnerable-lib",
            "vulnerability_id": "CVE-2023-7777",
            "analysis": "Analysis",
            "relevance": "RELEVANT", # LLM falsely claimed relevant
            "remediation": "Fix"
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            from guardian.reasoning.schemas import parse_dependency_reasoning_response
            parsed = parse_dependency_reasoning_response(fake_response, task="dependency_reasoning")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-dep-9",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "CVE-2023-7777",
        "title": "Vulnerable Dependency: unused-vulnerable-lib (CVE-2023-7777)",
        "severity": "HIGH",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "unused-vulnerable-lib"
    }]

    new_state = agent.run(state)

    insight = new_state["ai_dependency_insights"][0]
    # Enforced INSUFFICIENT_EVIDENCE because usage snippet was NONE_DETECTED
    assert insight["relevance"] == "INSUFFICIENT_EVIDENCE"


# 10. Groq failure preserves deterministic results
def test_10_groq_failure_preserves_deterministic_results(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "dep_repo_10"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("requests==2.25.1\n")

    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_DEPENDENCY_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    class MockFailingGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(
                available=False,
                error="⚠️ AI explanation temporarily unavailable: Service Unavailable (HTTP 503)"
            )

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockFailingGateway)

    state = create_initial_state(
        scan_id="scan-dep-10",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    state["findings"] = [{
        "finding_id": "dep-1",
        "rule_id": "CVE-2021-9999",
        "title": "Vulnerable Dependency: requests (CVE-2021-9999)",
        "severity": "HIGH",
        "category": "dependency",
        "file_path": "requirements.txt",
        "package": "requests"
    }]

    new_state = agent.run(state)

    # Deterministic results intact
    assert len(new_state["findings"]) > 0
    assert new_state["dependency_context"]["total_dependencies"] == 1
    # AI status updated gracefully without failing scan
    assert new_state["dependency_context"]["grok_status"] == "PROVIDER_UNAVAILABLE"


def test_11_token_admission_prevents_calls_over_agent_cap(tmp_path, monkeypatch):
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"dependency": 100})
    monkeypatch.setattr("guardian.reasoning.gateway.get_scan_token_tracker", lambda sid: tracker)

    # Consume most of token cap for dependency agent
    admitted1, _, _, _, _ = tracker.admit_request("dependency", 90) # Admitted, spent = 90
    assert admitted1 is True

    # Next call exceeds the 100 token cap for dependency agent
    admitted2, decision, rem, cap, usable = tracker.admit_request("dependency", 50)
    assert admitted2 is False
    assert decision == "SKIPPED_AGENT_CAP"


# 12 & 13. Successful AI insights preserved across supersteps & stable IDs prevent duplicates
def test_12_and_13_stable_ids_and_merge_list_deduplication():
    insight1 = {
        "id": "DEP-INSIGHT-abc123hash",
        "insight_id": "DEP-INSIGHT-abc123hash",
        "package": "requests",
        "vulnerability_id": "CVE-2023-1111",
        "analysis": "Critical SSRF"
    }

    insight2 = dict(insight1)

    merged = merge_list([insight1], [insight2])
    assert len(merged) == 1
    assert merged[0]["id"] == "DEP-INSIGHT-abc123hash"


# 14. API correctly exposes AI dependency insights
def test_14_api_exposes_ai_dependency_insights(tmp_path):
    curated = {
        "scan_id": "scan-dep-api",
        "active_agent": "IDLE",
        "completed_agents": ["dependency"],
        "dependency_context": {
            "total_dependencies": 1,
            "vulnerable_dependencies_count": 1,
            "grok_status": "COMPLETED",
        },
        "ai_dependency_insights": [{
            "id": "DEP-INSIGHT-xyz",
            "package": "requests",
            "vulnerability_id": "CVE-2023-1111",
            "relevance": "RELEVANT"
        }]
    }

    assert "ai_dependency_insights" in _STATE_KEYS
    record = {"source_scan_id": "base-123", "status": "COMPLETED", "scan_mode": "full_scan"}
    res = _build_agentic_analysis_result("scan-dep-api", record, curated)

    assert "ai_dependency_insights" in res
    assert len(res["ai_dependency_insights"]) == 1
    assert res["ai_dependency_insights"][0]["id"] == "DEP-INSIGHT-xyz"
    assert "ai_dependency_insights" in res["dependency_analysis"]


# 15. Existing frontend dependency metrics/pagination remain unchanged
def test_15_frontend_dependency_metrics_and_pagination_guarantee():
    from tests.test_arch_dep_agentic_flow import test_dependency_agent_metric_semantics
    test_dependency_agent_metric_semantics()
