"""
Regression Test Suite for Business Intent State Propagation to Agentic Scan
=============================================================================
Verifies that:
1. Deterministic Business Intent results (alignment score, rules, findings) are preserved when Agentic Scan runs.
2. BusinessAgent receives INSUFFICIENT_EVIDENCE findings and is eligible for AI reasoning.
3. Agentic Scan does NOT produce 'SKIPPED (Conclusive Baseline)' when INSUFFICIENT_EVIDENCE exists.
4. Conclusive deterministic results (0 INSUFFICIENT findings) DO produce 'SKIPPED (Conclusive Baseline)'.
5. Empty / no-document scans do NOT fabricate a conclusive zero-rule baseline.
6. Deterministic results are never overwritten by empty 0-rule agentic results.
"""
from __future__ import annotations

import json
import pytest
from typing import Any, Dict
from guardian.agents.business.agent import BusinessAgent
from backend.app.api.v1.agentic_scan import _adopt_deterministic_report, _build_agentic_analysis_result
from guardian.orchestrator.state import create_initial_state


def test_1_deterministic_result_preserved_during_agentic_adoption():
    """TEST 1: Deterministic result with alignment_score=0.25, total_rules=5, 1 INSUFFICIENT_EVIDENCE remains intact during adoption."""
    det_report = {
        "scan_id": "scan_test_adoption_1",
        "target": "C:/projects/DV_Bookshop",
        "repository": {"root": "C:/projects/DV_Bookshop"},
        "scan": {
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT", "score": 1.0},
                {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE", "score": 0.0},
                {"rule_id": "REQ-003", "status": "VIOLATION", "score": 0.0},
                {"rule_id": "REQ-004", "status": "PARTIAL", "score": 0.5},
                {"rule_id": "REQ-005", "status": "COMPLIANT", "score": 1.0},
            ]
        },
        "business_intent": {
            "status": "SUCCESS",
            "alignment_score": 0.25,
            "alignment_percentage": 25,
            "total_rules": 5,
            "matched": 2,
            "violated": 1,
            "partial": 1,
            "insufficient": 1,
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT"},
                {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE"},
                {"rule_id": "REQ-003", "status": "VIOLATION"},
                {"rule_id": "REQ-004", "status": "PARTIAL"},
                {"rule_id": "REQ-005", "status": "COMPLIANT"},
            ]
        }
    }

    adopted = _adopt_deterministic_report(det_report)
    biz_res = adopted.get("business_intent_results")

    assert biz_res is not None, "Adopted report must include business_intent_results"
    assert biz_res.get("alignment_percentage") == 25, f"Expected 25% alignment, got {biz_res.get('alignment_percentage')}"
    assert biz_res.get("total_rules") == 5, f"Expected 5 rules, got {biz_res.get('total_rules')}"
    assert len(biz_res.get("findings", [])) == 5, f"Expected 5 findings, got {len(biz_res.get('findings', []))}"


def test_2_business_agent_eligibility_insufficient_evidence(monkeypatch):
    """TEST 2: BusinessAgent receives the INSUFFICIENT_EVIDENCE finding and is eligible for reasoning."""
    monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")
    monkeypatch.setenv("BUSINESS_API_KEY", "dummy_key")

    captured_requests = []

    fake_response = json.dumps({
        "summary": "AI Business Analysis resolved insufficient evidence policy",
        "findings": [{
            "evidence_ids": ["E1"],
            "category": "Business Intent",
            "severity": "High",
            "confidence": 0.9,
            "title": "REQ-002",
            "reason": "Analyzed code context for policy REQ-002",
            "recommendation": "Add transactional wrapper around balance transfer",
            "file": "payment.py",
            "line": 10,
            "function": "transfer_balance",
            "extras": {"verdict": "VIOLATION", "policy_id": "REQ-002"}
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.schemas import parse_reasoning_response
            parsed = parse_reasoning_response(fake_response, task="business_intent", model="gemini-3.5-flash-lite")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    state = create_initial_state(
        scan_id="scan_test_eligibility",
        repository_profile={"repo_path": "C:/projects/DV_Bookshop"},
        business_intent_results={
            "status": "SUCCESS",
            "alignment_score": 0.25,
            "alignment_percentage": 25,
            "total_rules": 5,
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT"},
                {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE"},
                {"rule_id": "REQ-003", "status": "VIOLATION"},
                {"rule_id": "REQ-004", "status": "PARTIAL"},
                {"rule_id": "REQ-005", "status": "COMPLIANT"},
            ]
        }
    )

    agent = BusinessAgent()
    res = agent._process(state)

    assert len(captured_requests) == 1, "INSUFFICIENT_EVIDENCE MUST trigger Gemini reasoning"
    assert res["business_intent_results"]["grok_status"] == "COMPLETED"
    assert len(res.get("ai_business_insights", [])) == 1
    assert res["ai_business_insights"][0]["policy_id"] == "REQ-002"


def test_3_agentic_scan_not_produce_false_conclusive_baseline(monkeypatch):
    """TEST 3: Agentic Scan must NOT produce SKIPPED (Conclusive Baseline) when deterministic result contains INSUFFICIENT_EVIDENCE."""
    monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")
    monkeypatch.setenv("BUSINESS_API_KEY", "dummy_key")

    state = create_initial_state(
        scan_id="scan_test_no_false_conclusive",
        repository_profile={"repo_path": "C:/projects/DV_Bookshop"},
        business_intent_results={
            "status": "SUCCESS",
            "alignment_score": 0.25,
            "total_rules": 5,
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT"},
                {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE"},
            ]
        }
    )

    agent = BusinessAgent()
    res = agent._process(state)

    reason = res["business_intent_results"].get("agent_reason", "")
    assert "conclusive baseline" not in reason.lower(), f"Must NOT claim conclusive baseline when INSUFFICIENT_EVIDENCE present! Got: {reason}"


def test_4_conclusive_deterministic_result_produces_skipped_conclusive_baseline(monkeypatch):
    """TEST 4: A genuinely conclusive deterministic result (0 INSUFFICIENT findings) produces SKIPPED (Conclusive Baseline)."""
    monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")
    monkeypatch.setenv("BUSINESS_API_KEY", "dummy_key")

    state = create_initial_state(
        scan_id="scan_test_conclusive",
        repository_profile={"repo_path": "C:/projects/DV_Bookshop"},
        business_intent_results={
            "status": "SUCCESS",
            "alignment_score": 1.0,
            "total_rules": 3,
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT"},
                {"rule_id": "REQ-003", "status": "VIOLATION"},
                {"rule_id": "REQ-004", "status": "PARTIAL"},
            ]
        }
    )

    agent = BusinessAgent()
    res = agent._process(state)

    reason = res["business_intent_results"].get("agent_reason", "")
    assert res["business_intent_results"]["grok_status"] == "SKIPPED"
    assert "conclusive baseline" in reason.lower(), f"Expected conclusive baseline message, got: {reason}"


def test_5_no_document_scan_does_not_fabricate_conclusive_baseline(monkeypatch):
    """TEST 5: Agentic Scan with no business document must return NO_DOCUMENTS message and NOT claim conclusive baseline."""
    monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")
    monkeypatch.setenv("BUSINESS_API_KEY", "dummy_key")

    state = create_initial_state(
        scan_id="scan_test_empty",
        repository_profile={"repo_path": "C:/projects/empty_workspace"},
        business_intent_results={
            "status": "NO_DOCUMENTS",
            "alignment_score": 0.0,
            "total_rules": 0,
            "findings": []
        }
    )

    agent = BusinessAgent()
    res = agent._process(state)

    reason = res["business_intent_results"].get("agent_reason", "")
    assert "conclusive baseline" not in reason.lower(), f"Must NOT claim conclusive baseline for 0-rule scan! Got: {reason}"
    assert "No business requirements documents found" in reason or "NO_BUSINESS_REQUIREMENTS" in reason


def test_6_build_agentic_analysis_result_preserves_deterministic_business_results():
    """TEST 6: _build_agentic_analysis_result retains total_rules, alignment_score, and findings in business_analysis.results."""
    curated = {
        "business_violations": [{"rule_id": "REQ-003"}],
        "business_intent_results": {
            "status": "SUCCESS",
            "alignment_score": 0.25,
            "alignment_percentage": 25,
            "total_rules": 5,
            "findings": [
                {"rule_id": "REQ-001", "status": "COMPLIANT"},
                {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE"},
                {"rule_id": "REQ-003", "status": "VIOLATION"},
                {"rule_id": "REQ-004", "status": "PARTIAL"},
                {"rule_id": "REQ-005", "status": "COMPLIANT"},
            ]
        },
        "ai_business_insights": []
    }

    record = {"scan_id": "scan_test_build"}
    res = _build_agentic_analysis_result("scan_test_build", record, curated)

    biz_an = res["business_analysis"]
    assert biz_an["results"] is not None, "business_analysis.results must not be None"
    assert biz_an["results"]["total_rules"] == 5, f"Expected 5 total rules, got {biz_an['results']['total_rules']}"
    assert biz_an["results"]["alignment_percentage"] == 25, f"Expected 25%, got {biz_an['results']['alignment_percentage']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
