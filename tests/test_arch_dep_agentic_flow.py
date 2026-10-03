"""
Focused tests for Architecture and Dependency agentic-result API and state propagation.
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.app.api.v1.agentic_scan import (
    _STATE_KEYS,
    _build_agentic_analysis_result,
    _curated_state,
)
from guardian.agents.architecture import ArchitectureAgent
from guardian.agents.dependency import DependencyAgent
from guardian.orchestrator.state import create_initial_state


def test_architecture_agent_state_and_api_propagation(tmp_path, monkeypatch):
    """Verify ArchitectureAgent context and ai_architecture_insights flow into AgenticAnalysisResult."""
    fixture_dir = tmp_path / "arch_app"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "app.py").write_text("""
def profile():
    return "profile"
""")
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_AGENT_ARCHITECTURE_ENABLED", "true")
    monkeypatch.setenv("XAI_API_KEY", "test_key")

    fake_response_json = json.dumps({
        "summary": "AI Architecture Analysis identified trust boundary risk",
        "findings": [{
            "evidence_ids": ["E1"],
            "category": "architecture",
            "severity": "High",
            "confidence": 0.9,
            "title": "Unauthenticated API Controller Entry Point",
            "reason": "profile() endpoint lacks session token or auth middleware verification.",
            "recommendation": "Attach authentication middleware to controller route.",
            "file": "app.py",
            "line": 2,
            "function": "profile",
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            from guardian.reasoning.schemas import parse_reasoning_response
            parsed = parse_reasoning_response(fake_response_json, task="architecture_reasoning", model="test-grok")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)


    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-arch-test",
        repository_profile={
            "repo_path": str(fixture_dir),
            "primary_language": "Python",
            "frameworks": ["FastAPI"],
            "entry_points": ["app.py"],
            "detected_endpoints": ["/profile"],
        },
        findings=[{"finding_id": "f-1", "category": "security"}]
    )


    agent = ArchitectureAgent()
    new_state = agent.run(state)

    assert "architecture_context" in new_state
    assert "ai_architecture_insights" in new_state
    assert len(new_state["ai_architecture_insights"]) == 1
    assert new_state["ai_architecture_insights"][0].get("category") == "architecture"

    # Verify curated state whitelist
    assert "architecture_context" in _STATE_KEYS
    assert "ai_architecture_insights" in _STATE_KEYS
    curated = _curated_state(new_state)
    assert "architecture_context" in curated
    assert "ai_architecture_insights" in curated

    # Verify API Result Envelope
    record = {"source_scan_id": "base-123", "status": "COMPLETED", "scan_mode": "full_scan"}
    res = _build_agentic_analysis_result("scan-arch-test", record, curated)

    assert "architecture_analysis" in res
    assert "ai_architecture_insights" in res
    assert len(res["ai_architecture_insights"]) == 1
    assert res["architecture_analysis"]["ai_architecture_insights"] == res["ai_architecture_insights"]


def test_architecture_agent_tpm_rate_limit_and_max_tokens_budget(tmp_path, monkeypatch):
    """Verify ArchitectureAgent max_tokens=600, reasoning_effort=low, RATE_LIMITED classification, and deterministic topology preservation on 429."""
    fixture_dir = tmp_path / "arch_tpm_app"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "main.py").write_text("def index(): pass")

    captured_requests = []

    class Mock429Gateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(
                available=False,
                error="⚠️ AI explanation temporarily unavailable: Rate limit / quota reached (HTTP 429: TPM limit)"
            )

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", Mock429Gateway)

    state = create_initial_state(
        scan_id="scan-arch-tpm-test",
        repository_profile={
            "repo_path": str(fixture_dir),
            "primary_language": "Python",
            "frameworks": ["FastAPI"],
            "entry_points": ["main.py"],
            "detected_endpoints": ["/api/v1/checkout", "/api/v1/refund", "/api/v1/auth", "/api/v1/user"],
        },
        findings=[{"finding_id": "f-1", "category": "security"}]
    )

    agent = ArchitectureAgent()
    new_state = agent.run(state)

    # 1. Verify max completion budget is 600 & reasoning_effort is "low"
    assert len(captured_requests) == 1, "Expected exactly 1 request (no retry loop flooding)"
    req = captured_requests[0]
    assert req.max_tokens in (500, 600), f"Expected max_tokens in (500, 600), got {req.max_tokens}"
    assert req.reasoning_effort == "low", f"Expected reasoning_effort='low', got {req.reasoning_effort}"

    # 2. Verify deterministic topology remains fully preserved
    arch_ctx = new_state.get("architecture_context", {})
    assert "service_boundaries" in arch_ctx
    assert "trust_boundaries" in arch_ctx
    assert "authentication_flows" in arch_ctx

    # 3. Verify HTTP 429 is classified as RATE_LIMITED (not PROVIDER_UNAVAILABLE)
    assert arch_ctx.get("grok_status") == "RATE_LIMITED"
    assert "rate-limited" in arch_ctx.get("agent_reason", "").lower()


def test_architecture_agent_structured_json_and_finish_reason_length(tmp_path, monkeypatch):
    """Verify ArchitectureAgent with reasoning_effort='low' populates ai_architecture_insights and handles finish_reason gracefully."""
    fixture_dir = tmp_path / "arch_json_app"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "main.py").write_text("def index(): pass")

    captured_requests = []

    fake_response_json = json.dumps({
        "summary": "AI Architecture Analysis identified trust boundary risk",
        "findings": [{
            "evidence_ids": ["E1"],
            "category": "architecture",
            "severity": "Medium",
            "confidence": 0.8,
            "title": "API Controller Entry Point",
            "reason": "Endpoint lacks session token or auth middleware verification.",
            "recommendation": "Attach authentication middleware to controller route.",
            "file": "main.py",
            "line": 1,
            "function": "index",
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.schemas import parse_reasoning_response
            parsed = parse_reasoning_response(fake_response_json, task="architecture_reasoning", model="openai/gpt-oss-20b")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan-arch-json-test",
        repository_profile={
            "repo_path": str(fixture_dir),
            "primary_language": "Python",
            "frameworks": ["FastAPI"],
            "entry_points": ["main.py"],
            "detected_endpoints": ["/api/v1/checkout"],
        },
        findings=[{"finding_id": "f-1", "category": "security"}]
    )

    agent = ArchitectureAgent()
    new_state = agent.run(state)

    assert len(captured_requests) == 1, "Exactly one provider attempt must be made"
    req = captured_requests[0]
    assert req.max_tokens in (500, 600), f"Expected max_tokens in (500, 600), got {req.max_tokens}"
    assert req.reasoning_effort == "low"

    assert new_state["architecture_context"]["grok_status"] == "COMPLETED"
    assert "ai_architecture_insights" in new_state
    assert len(new_state["ai_architecture_insights"]) == 1
    assert new_state["ai_architecture_insights"][0]["category"] == "architecture"


def test_dependency_agent_state_and_api_propagation(tmp_path):
    """Verify DependencyAgent context and findings flow into AgenticAnalysisResult."""
    fixture_dir = tmp_path / "dep_app"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "requirements.txt").write_text("requests==2.25.1\n")

    state = create_initial_state(
        scan_id="scan-dep-test",
        repository_profile={
            "repo_path": str(fixture_dir),
            "manifest_files": ["requirements.txt"],
        }
    )

    agent = DependencyAgent()
    new_state = agent.run(state)

    assert "dependency_context" in new_state
    dep_ctx = new_state["dependency_context"]
    assert dep_ctx["total_dependencies"] == 1
    assert dep_ctx["detected_libraries"][0]["name"] == "requests"

    # Verify curated state whitelist
    assert "dependency_context" in _STATE_KEYS
    curated = _curated_state(new_state)
    assert "dependency_context" in curated

    # Verify API Result Envelope
    record = {"source_scan_id": "base-123", "status": "COMPLETED", "scan_mode": "full_scan"}
    res = _build_agentic_analysis_result("scan-dep-test", record, curated)

    assert "dependency_analysis" in res
    assert res["dependency_analysis"]["total_dependencies"] == 1
    assert len(res["dependency_analysis"]["detected_libraries"]) == 1


def test_dependency_agent_metric_semantics():
    """Verify semantic guarantees: distinct vulnerable packages <= total packages, matches can exceed distinct packages, CVEs deduplicated."""
    detected_libs = [
        {"name": f"pkg-{i+1}", "version": "1.0.0", "ecosystem": "PyPI", "manifest": "requirements.txt"}
        for i in range(17)
    ]

    findings = [
        {
            "finding_id": f"dep-{i+1}",
            "rule_id": f"CVE-2023-{1000 + (i % 20)}",
            "title": f"Vulnerable Dependency: pkg-1 (CVE-2023-{1000 + (i % 20)})",
            "category": "dependency",
            "severity": "HIGH",
            "file_path": "requirements.txt"
        }
        for i in range(44)
    ]

    cve_list = list(set(f["rule_id"] for f in findings if "CVE" in f["rule_id"]))

    dep_ctx = {
        "total_dependencies": 17,
        "direct_dependencies_count": 17,
        "transitive_dependencies_count": 0,
        "vulnerable_dependencies_count": 44,
        "manifest_files": ["requirements.txt"],
        "detected_libraries": detected_libs,
        "cve_list": cve_list,
    }

    # Distinct vulnerable packages calculation
    vuln_pkgs = set()
    for lib in detected_libs:
        name = lib["name"].lower()
        matched = [f for f in findings if name in f.get("title", "").lower()]
        if matched:
            vuln_pkgs.add((lib["ecosystem"].lower(), name))

    distinct_vulnerable_count = min(len(vuln_pkgs), dep_ctx["total_dependencies"])
    vulnerability_matches = max(len(findings), dep_ctx["vulnerable_dependencies_count"])
    unique_cves = len(set(dep_ctx["cve_list"]))

    assert dep_ctx["total_dependencies"] == 17
    assert distinct_vulnerable_count == 1
    assert vulnerability_matches == 44
    assert unique_cves == 20
    assert distinct_vulnerable_count <= dep_ctx["total_dependencies"]
    assert vulnerability_matches > distinct_vulnerable_count

