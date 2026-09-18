"""
AI Code Guardian v3 — Phase 5 Unit Tests
========================================
Tests for ThreatSimulationAgent, PolicyAgent, RiskFusionAgent, PolicyPackManager,
EvidenceCorrelationService, ReasoningConsensus, KnowledgeService expansion,
and expanded StateGraph workflow.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.agents import (
    PolicyAgent,
    ReasoningConsensus,
    RiskFusionAgent,
    ThreatSimulationAgent,
)
from guardian.evidence.correlation import EvidenceCorrelationService
from guardian.knowledge.services.knowledge_service import KnowledgeService
from guardian.orchestrator import (
    OrchestratorWorkflow,
    create_initial_state,
)
from guardian.policies import PolicyPack, PolicyPackManager, PolicyRule


def test_threat_simulation_agent():
    state = create_initial_state(
        scan_id="scan-threat",
        findings=[{
            "finding_id": "f-1",
            "rule_id": "SEC-004",
            "file_path": "auth/login.py",
            "severity": "CRITICAL",
            "evidence_id": "ev-1",
        }],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
        repository_context={"entry_points": ["auth/login.py"], "public_apis": ["/api/login"]},
        business_context={"criticality": "CRITICAL"},
    )

    agent = ThreatSimulationAgent()
    res = agent.run(state)

    assert res["active_agent"] == "threat_simulation"
    assert "threat_simulation" in res["completed_agents"]

    ctx = res["threat_context"]
    assert ctx["exploitability"] >= 0.8
    assert len(res["attack_paths"]) == 1
    assert res["attack_paths"][0]["evidence_id"] == "ev-1"


def test_policy_pack_manager_and_agent():
    mgr = PolicyPackManager()
    assert "OWASP_TOP_10" in mgr.list_packs()
    assert "NIST_800_53" in mgr.list_packs()

    state = create_initial_state(
        scan_id="scan-pol",
        findings=[{
            "finding_id": "f-2",
            "rule_id": "POL-OWASP-A01",
            "category": "access_control",
            "severity": "HIGH",
        }],
        policy_context={"frameworks": ["OWASP_TOP_10"]},
    )

    agent = PolicyAgent(policy_manager=mgr)
    res = agent.run(state)

    assert res["active_agent"] == "policy"
    assert "policy" in res["completed_agents"]

    p_res = res["policy_results"]
    assert p_res["total_violations"] > 0
    assert "OWASP_TOP_10" in p_res["failed_policies"]


def test_evidence_correlation_service():
    service = EvidenceCorrelationService()
    findings = [
        {"finding_id": "f-1", "rule_id": "SEC-001", "file_path": "main.py", "line_number": 10},
        {"finding_id": "f-1-dup", "rule_id": "SEC-001", "file_path": "main.py", "line_number": 10},
    ]
    evidence = [{"evidence_id": "ev-1", "finding_id": "f-1"}]
    threat = {"attack_paths": [{"finding_id": "f-1", "title": "Chain 1", "exploitability": 0.9}]}

    corr = service.correlate(findings, evidence, threat_context=threat)

    assert corr["total_correlated"] == 1
    assert len(corr["chains"]) == 1
    assert corr["chains"][0]["evidence_ids"] == ["ev-1"]


def test_reasoning_consensus():
    engine = ReasoningConsensus()
    findings = [{"finding_id": "f-1", "evidence_id": "ev-1"}]
    arch = {"trust_boundaries": ["Gateway -> App"]}
    threat = {"attack_paths": [{"finding_id": "f-1"}]}

    conf = engine.calculate_confidence(findings, arch, threat)
    assert 0.0 <= conf <= 1.0
    assert conf >= 0.80


def test_knowledge_service_expansion():
    service = KnowledgeService()

    pol_ctx = service.get_policy_context()
    assert isinstance(pol_ctx, list)

    biz_ctx = service.get_business_context()
    assert isinstance(biz_ctx, list)

    threat_ctx = service.get_threat_context()
    assert isinstance(threat_ctx, list)

    service.close()


def test_risk_fusion_agent():
    state = create_initial_state(
        scan_id="scan-risk",
        findings=[{"finding_id": "f-1", "severity": "CRITICAL", "evidence_id": "ev-1"}],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
        business_context={"criticality": "CRITICAL"},
        threat_context={"exploitability": 0.95, "reachability": 1.0},
        policy_results={"total_violations": 2, "violations": []},
    )

    agent = RiskFusionAgent()
    res = agent.run(state)

    assert res["active_agent"] == "risk_fusion"
    assert "risk_fusion" in res["completed_agents"]

    risk_prof = res["risk_scores"]
    assert risk_prof["composite_risk_score"] > 0.0
    assert risk_prof["confidence_score"] > 0.0
    assert "total_correlated" in res["correlated_findings"]


def test_full_phase5_langgraph_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "main.py").write_text("import fastapi\nAWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'\n")
        (tmp_path / "requirements.txt").write_text("fastapi\nrequests==2.25.1\n")

        workflow = OrchestratorWorkflow()

        final_state = workflow.execute(
            scan_id="scan-phase5-full",
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

        assert final_state["scan_id"] == "scan-phase5-full"

        completed = final_state["completed_agents"]
        expected_agents = [
            "planner", "repository", "business", "security",
            "architecture", "dependency", "threat_simulation", "policy", "risk_fusion"
        ]
        for ag in expected_agents:
            assert ag in completed, f"Agent '{ag}' missing from completed_agents: {completed}"

        assert final_state["active_agent"] in ("risk_fusion", "validation")

        # Verify all intelligence context structures exist in state
        assert "exploitability" in final_state["threat_context"]
        assert "total_violations" in final_state["policy_results"]
        assert "composite_risk_score" in final_state["risk_scores"]
        assert "total_correlated" in final_state["correlated_findings"]

        # Verify metrics & traces
        metrics = final_state["execution_metrics"]
        assert len(metrics["agent_runtime"]) >= 9
