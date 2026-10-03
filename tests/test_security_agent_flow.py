"""
AI Code Guardian v3 — Security Agent Flow Unit & Integration Tests
===================================================================
Tests for SecurityAgent state machine, Phase 5 AI-need gating, ReasoningGateway
integration, Grok status reporting, Threat Simulation, and Risk Fusion.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from guardian.agents.security.agent import SecurityAgent
from guardian.agents.threat_simulation.agent import ThreatSimulationAgent
from guardian.agents.risk.agent import RiskFusionAgent
from guardian.orchestrator.state import create_initial_state
from guardian.reasoning.gateway import ReasoningResult
from guardian.reasoning.schemas import ReasoningResponse, ReasoningFinding


def test_security_agent_scenario_a_grok_skipped():
    """Scenario A: Conclusive deterministic baseline -> should_call_grok is False.
    SecurityAgent sets grok_status to SKIPPED with clear reason.
    """
    state = create_initial_state(
        scan_id="scan-conclusive-01",
        findings=[{
            "finding_id": "f-low-1",
            "rule_id": "SEC-STYLE-001",
            "title": "Minor Code Formatting Concern",
            "severity": "LOW",
            "confidence": 0.95,
            "file": "utils/helpers.py",
            "line": 12,
            "evidence_id": "ev-1",
        }],
        evidence=[{"id": "ev-1", "file": "utils/helpers.py", "line": 12, "snippet": "x = 1"}],
        repository_profile={"repo_path": ".", "total_files": 10},
    )

    agent = SecurityAgent()
    res = agent.run(state)

    sec_ctx = res.get("security_context", {})
    assert sec_ctx.get("grok_status") == "SKIPPED"
    assert "conclusive baseline" in sec_ctx.get("agent_reason", "").lower()
    assert len(res.get("ai_security_insights", [])) == 0


def test_security_agent_scenario_b_grok_evaluated_success():
    """Scenario B: High risk/auth/sql keyword finding -> should_call_grok is True.
    ReasoningGateway returns AI findings which are attached as source=AI_VALIDATED.
    """
    state = create_initial_state(
        scan_id="scan-semantic-02",
        findings=[{
            "finding_id": "f-sql-1",
            "rule_id": "SEC-SQL-INJECTION",
            "title": "Potential SQL Injection",
            "severity": "HIGH",
            "confidence": 0.90,
            "file": "auth/db.py",
            "line": 45,
            "evidence_id": "ev-sql-1",
        }],
        evidence=[{
            "id": "ev-sql-1",
            "file": "auth/db.py",
            "line": 45,
            "snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_input)",
        }],
        repository_profile={"repo_path": ".", "total_files": 15},
    )

    mock_ai_finding = ReasoningFinding(
        category="SQL_INJECTION",
        severity="HIGH",
        title="Framework ORM Bypass SQL Injection",
        reason="Direct string concatenation in cursor.execute bypasses SQLAlchemy ORM sanitization.",
        file="auth/db.py",
        line=45,
        evidence_ids=["ev-sql-1"],
        recommendation="Use parameterized queries cursor.execute('SELECT * FROM users WHERE id=?', (user_input,))",
        confidence=0.88,
    )

    mock_reason_resp = ReasoningResponse(
        task="security_reasoning",
        model="groq/openai/gpt-oss-120b",
        findings=[mock_ai_finding],
    )
    mock_result = ReasoningResult(available=True, response=mock_reason_resp)

    with patch("guardian.reasoning.gateway.ReasoningGateway.reason", return_value=mock_result), \
         patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
         patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
        agent = SecurityAgent()
        res = agent.run(state)

    sec_ctx = res.get("security_context", {})
    assert sec_ctx.get("grok_status") == "COMPLETED"
    assert "ai_security_insights" in res
    insights = res["ai_security_insights"]
    assert len(insights) == 1
    assert insights[0]["source"] == "AI_VALIDATED"
    assert insights[0]["engine"] == "grok_security_reasoning"
    assert "SQL" in insights[0]["rule_id"]


def test_security_agent_grok_rate_limited_fallback():
    """Scenario: Grok returns HTTP 429 rate limit or error.
    SecurityAgent handles gracefully, sets grok_status to FAILED, and records reason.
    """
    state = create_initial_state(
        scan_id="scan-rate-limit-03",
        findings=[{
            "finding_id": "f-auth-1",
            "rule_id": "SEC-AUTH-BYPASS",
            "title": "Authentication Bypass Vulnerability",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "file": "auth/jwt.py",
            "line": 10,
            "evidence_id": "ev-auth-1",
        }],
        evidence=[{"id": "ev-auth-1", "file": "auth/jwt.py", "line": 10}],
        repository_profile={"repo_path": ".", "total_files": 5},
    )

    mock_result = ReasoningResult(
        available=False,
        error="LLM API rate limit exceeded (HTTP 429).",
    )

    with patch("guardian.reasoning.gateway.ReasoningGateway.reason", return_value=mock_result), \
         patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
         patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
        agent = SecurityAgent()
        res = agent.run(state)

    sec_ctx = res.get("security_context", {})
    assert sec_ctx.get("grok_status") == "RATE_LIMITED"
    assert "rate limit" in sec_ctx.get("agent_reason", "").lower()
    assert len(res.get("ai_security_insights", [])) == 0


def test_threat_simulation_and_risk_fusion_with_ai_findings():
    """Downstream agents (ThreatSimulation, RiskFusion) process both deterministic and AI findings cleanly."""
    state = create_initial_state(
        scan_id="scan-integration-04",
        findings=[
            {
                "finding_id": "f-det-1",
                "rule_id": "SEC-001",
                "title": "Hardcoded Secret",
                "severity": "HIGH",
                "file": "config.py",
                "line": 5,
                "evidence_id": "ev-det-1",
            },
            {
                "finding_id": "ai-sec-12345",
                "rule_id": "AI-SEC-SQL_INJECTION",
                "title": "Semantic SQL Injection",
                "severity": "CRITICAL",
                "file": "db.py",
                "line": 20,
                "evidence_id": "ev-ai-1",
                "source": "AI_VALIDATED",
                "engine": "grok_security_reasoning",
            }
        ],
        evidence=[
            {"id": "ev-det-1", "file": "config.py", "line": 5},
            {"id": "ev-ai-1", "file": "db.py", "line": 20},
        ],
        repository_context={"entry_points": ["db.py"], "public_apis": ["/api/query"]},
        business_context={"criticality": "CRITICAL"},
    )

    threat_agent = ThreatSimulationAgent()
    state_threat = threat_agent.run(state)
    assert "threat_simulation" in state_threat["completed_agents"]
    assert len(state_threat.get("attack_paths", [])) >= 1

    risk_agent = RiskFusionAgent()
    state_risk = risk_agent.run(state_threat)
    assert "risk_fusion" in state_risk["completed_agents"]
    assert "composite_risk_score" in state_risk.get("risk_scores", {})
    assert state_risk["risk_scores"]["composite_risk_score"] > 0


def test_general_security_candidate_selection():
    """Verify that general security relevance scoring ranks route/auth/DB endpoints higher than generic helpers."""
    from pathlib import Path
    from guardian.intent.matcher.rule_matcher import RuleMatcher

    multi_app_dir = Path("tests/fixtures/multi_file_app").resolve()
    ws_profiles = RuleMatcher._profiles_from_workspace(multi_app_dir)

    assert len(ws_profiles) > 0
    # Top profiles sorted by security_score descending
    top_profiles = sorted(ws_profiles, key=lambda p: getattr(p, "security_score", 0.0), reverse=True)
    top_fn_names = [p.function_name for p in top_profiles[:3]]

    assert "fetch_user_document" in top_fn_names
    assert "require_auth" in top_fn_names
    assert top_profiles[0].security_score > 5.0


def test_multi_file_app_agentic_scan_context():
    """Verify SecurityAgent selects relevant candidates and formats bounded source snippets for ReasoningGateway."""
    from pathlib import Path
    multi_app_dir = Path("tests/fixtures/multi_file_app").resolve()

    state = create_initial_state(
        scan_id="scan-multi-app-05",
        findings=[],
        evidence=[],
        repository_profile={"repo_path": str(multi_app_dir), "total_files": 4},
    )

    mock_reason_resp = ReasoningResponse(
        task="security_reasoning",
        model="groq/openai/gpt-oss-120b",
        findings=[],
    )
    mock_result = ReasoningResult(available=True, response=mock_reason_resp)

    captured_request = []

    def mock_reason(request):
        captured_request.append(request)
        return mock_result

    with patch("guardian.reasoning.gateway.ReasoningGateway.reason", side_effect=mock_reason), \
         patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
         patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
        agent = SecurityAgent()
        res = agent.run(state)

    sec_ctx = res.get("security_context", {})
    assert sec_ctx.get("grok_status") == "COMPLETED"
    assert len(captured_request) == 1

    ev_block = captured_request[0].evidence_block
    assert "fetch_user_document" in ev_block
    assert "Source Snippet:" in ev_block


def test_candidate_enrichment_when_deterministic_findings_ge_5():
    """Regression Test: Verify workspace candidate snippets are included even when deterministic findings >= 5."""
    from pathlib import Path
    multi_app_dir = Path("tests/fixtures/multi_file_app").resolve()

    # Create 6 deterministic findings and evidence items (>= 5)
    findings = [
        {
            "finding_id": f"f-{i}",
            "rule_id": "SEC-AUTH-CHECK",
            "title": f"Auth finding {i}",
            "severity": "HIGH",
            "confidence": 0.9,
            "file": f"dummy_{i}.py",
            "line": i * 10,
            "evidence_id": f"ev:{i}",
        }
        for i in range(1, 7)
    ]
    evidence = [
        {
            "id": f"ev:{i}",
            "file": f"dummy_{i}.py",
            "line": i * 10,
            "snippet": f"print({i})",
        }
        for i in range(1, 7)
    ]

    state = create_initial_state(
        scan_id="scan-ge-5-findings",
        findings=findings,
        evidence=evidence,
        repository_profile={"repo_path": str(multi_app_dir), "total_files": 4},
    )

    mock_reason_resp = ReasoningResponse(
        task="security_reasoning",
        model="groq/openai/gpt-oss-120b",
        findings=[],
    )
    mock_result = ReasoningResult(available=True, response=mock_reason_resp)

    captured_request = []

    def mock_reason(request):
        captured_request.append(request)
        return mock_result

    with patch("guardian.reasoning.gateway.ReasoningGateway.reason", side_effect=mock_reason), \
         patch("guardian.reasoning.gateway.ReasoningGateway.configured", True), \
         patch("guardian.llm.config.LLMConfig.is_agent_enabled", return_value=True):
        agent = SecurityAgent()
        res = agent.run(state)

    sec_ctx = res.get("security_context", {})
    assert sec_ctx.get("grok_status") == "COMPLETED"
    assert len(captured_request) == 1

    ev_block = captured_request[0].evidence_block

    # Deterministic evidence items must all be present
    for i in range(1, 7):
        assert f"dummy_{i}.py" in ev_block

    # Workspace candidate snippets MUST also be included despite len(evidence) >= 5
    assert "fetch_user_document" in ev_block
    assert "Source Snippet:" in ev_block


def test_build_agentic_analysis_result_propagates_ai_security_insights():
    """Verify that _build_agentic_analysis_result() passes ai_security_insights into API result contract."""
    from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result

    mock_insights = [
        {
            "finding_id": "ai-sec-01",
            "rule_id": "AI-SEC-IDOR",
            "title": "Insecure Direct Object Reference",
            "severity": "HIGH",
            "category": "authorization",
            "file": "app.py",
            "line": 945,
            "source": "AI_VALIDATED",
            "engine": "grok_security_reasoning",
        },
        {
            "finding_id": "ai-sec-02",
            "rule_id": "AI-SEC-SSRF",
            "title": "Server-Side Request Forgery",
            "severity": "CRITICAL",
            "category": "ssrf",
            "file": "app.py",
            "line": 1801,
            "source": "AI_VALIDATED",
            "engine": "grok_security_reasoning",
        },
    ]

    record = {"source_scan_id": "scan_123", "status": "completed", "scan_mode": "full_scan", "started_at": 100.0}
    curated_state = {
        "scan_id": "agentic_456",
        "ai_security_insights": mock_insights,
        "completed_agents": ["security"],
    }

    result = _build_agentic_analysis_result("agentic_456", record, curated_state)

    # Top-level ai_security_insights MUST be present for agentic.result?.ai_security_insights
    assert "ai_security_insights" in result
    assert isinstance(result["ai_security_insights"], list)
    assert len(result["ai_security_insights"]) == 2
    assert result["ai_security_insights"][0]["finding_id"] == "ai-sec-01"
    assert result["ai_security_insights"][1]["rule_id"] == "AI-SEC-SSRF"

    # Also inside security_enrichment
    sec_enrichment = result.get("security_enrichment", {})
    assert "ai_security_insights" in sec_enrichment
    assert len(sec_enrichment["ai_security_insights"]) == 2


def test_build_agentic_analysis_result_empty_ai_security_insights():
    """Verify missing/empty ai_security_insights serializes as [] in API result contract."""
    from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result

    record = {"source_scan_id": "scan_123", "status": "completed", "scan_mode": "full_scan"}
    curated_state = {"scan_id": "agentic_456"}  # No ai_security_insights key

    result = _build_agentic_analysis_result("agentic_456", record, curated_state)

    assert "ai_security_insights" in result
    assert result["ai_security_insights"] == []
    sec_enrichment = result.get("security_enrichment", {})
    assert sec_enrichment.get("ai_security_insights") == []




