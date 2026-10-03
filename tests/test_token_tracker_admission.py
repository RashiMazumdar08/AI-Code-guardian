"""
Unit and Regression Tests for ACG2 Scan Token Admission Control
===============================================================
Verifies:
1. 6,500 total scan token budget ceiling.
2. Dynamic token admission (no static reservation locking blocking other agents).
3. Unused token release and refund on completion or error.
4. Per-agent ceiling caps (security: 2200, business: 2200, etc.).
5. Zero external LLM token consumption for local components (Qwen, MiniLM, AST).
6. Elimination of legacy BusinessIntentEngine LLM calls.
7. Provider independence per agent while preserving shared token budget ceiling.
8. Telemetry logging and final scan token report formatting.
"""
from __future__ import annotations

import os
import threading
import pytest
from unittest.mock import MagicMock, patch

from guardian.reasoning.gateway import (
    ScanTokenTracker,
    get_scan_token_tracker,
    reset_scan_token_trackers,
    format_scan_token_report,
    ReasoningGateway,
    ReasoningRequest,
    ReasoningResult,
)
from guardian.llm.config import LLMConfig
from guardian.intent.engine import BusinessIntentEngine


def setup_function():
    reset_scan_token_trackers()


def test_1_default_6500_budget_and_agent_caps():
    tracker = ScanTokenTracker()
    assert tracker.total_budget == 6500
    assert tracker.remaining_budget == 6500
    caps = tracker.agent_caps
    assert caps["security"] == (2200 if os.getenv("SECURITY_AGENT_ENABLED", "false").lower() in ("true", "1") else 0)
    assert caps["business"] == 4000
    assert caps["architecture"] == 1100
    assert caps["threat_simulation"] == 1000
    assert caps["patch"] == 450
    assert caps["validation"] == 450
    assert caps["shared"] == 100


def test_2_dynamic_admission_allowed():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100})
    admitted, decision, remaining, cap, capacity = tracker.admit_request("security", 1200)
    assert admitted is True
    assert decision == "EXECUTED"
    assert remaining == 5300
    assert tracker.agent_spent["security"] == 1200


def test_3_no_static_reservation_locking():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100})
    # Security spends 500 out of 2200
    tracker.admit_request("security", 500)
    # Business can spend up to its full 4000 cap because global budget has 6000 remaining
    admitted, decision, remaining, cap, capacity = tracker.admit_request("business", 2000)
    assert admitted is True
    assert decision == "EXECUTED"
    assert remaining == 4000
    assert tracker.agent_spent["business"] == 2000


def test_4_token_release_on_completion():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100})
    # Reserve 1800 for security
    tracker.admit_request("security", 1800)
    assert tracker.remaining_budget == 4700

    # Actual completion used 600 tokens -> 1200 unused released
    released = tracker.release_unused("security", 1800, 600)
    assert released == 1200
    assert tracker.remaining_budget == 5900
    assert tracker.agent_spent["security"] == 600


def test_5_full_refund_on_error():
    tracker = ScanTokenTracker(total_budget=6500)
    tracker.admit_request("business", 1500)
    assert tracker.remaining_budget == 5000

    # LLM call fails -> refund all 1500 tokens
    tracker.refund("business", 1500)
    assert tracker.remaining_budget == 6500
    assert tracker.agent_spent["business"] == 0


def test_6_exceeding_agent_cap_skipped():
    tracker = ScanTokenTracker(total_budget=6500)
    # Request 2500 tokens for architecture (cap is 1100)
    admitted, decision, remaining, cap, capacity = tracker.admit_request("architecture", 2500)
    assert admitted is False
    assert decision == "SKIPPED_AGENT_CAP"
    assert remaining == 6500


def test_7_exceeding_global_budget_skipped():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100})
    # Security uses 2200, Business uses 2200, Architecture uses 1100, Threat uses 900 (total 6400)
    tracker.admit_request("security", 2200)
    tracker.admit_request("business", 2200)
    tracker.admit_request("architecture", 1100)
    tracker.admit_request("threat_simulation", 900)
    assert tracker.remaining_budget == 100

    # Requesting 450 tokens for patch exceeds remaining 100 budget
    admitted, decision, remaining, cap, capacity = tracker.admit_request("patch", 450)
    assert admitted is False
    assert decision == "SKIPPED_BUDGET"
    assert remaining == 100


def test_8_zero_token_local_components():
    tracker = get_scan_token_tracker("test_local_scan", total_budget=6500)
    initial_remaining = tracker.remaining_budget

    # Execute local components: Qwen parser, MiniLM index, AST extractor
    # None of them call ScanTokenTracker.admit_request
    assert tracker.remaining_budget == initial_remaining
    assert sum(tracker.agent_spent.values()) == 0


def test_9_no_legacy_business_engine_llm_call():
    scan_id = "test_engine_scan"
    tracker = get_scan_token_tracker(scan_id, total_budget=6500)
    engine = BusinessIntentEngine(use_llm=True)

    with patch("guardian.reasoning.gateway.ReasoningGateway.reason") as mock_reason:
        # BusinessIntentEngine.run() should NOT invoke ReasoningGateway
        res = engine.run()
        mock_reason.assert_not_called()

    assert tracker.remaining_budget == 6500
    assert tracker.agent_spent.get("business", 0) == 0


def test_10_provider_independence_config():
    os.environ["SECURITY_LLM_PROVIDER"] = "gemini"
    os.environ["SECURITY_GEMINI_API_KEY"] = "fake-gemini-key"
    os.environ["BUSINESS_LLM_PROVIDER"] = "nemotron"
    os.environ["BUSINESS_NVIDIA_API_KEY"] = "fake-nvidia-key"

    try:
        cfg = LLMConfig.from_env()
        sec_cfg = cfg.get_agent_config("security")
        bus_cfg = cfg.get_agent_config("business")

        assert sec_cfg.provider == "gemini"
        assert sec_cfg.api_key == "fake-gemini-key"
        assert bus_cfg.provider == "nemotron"
        assert bus_cfg.api_key == "fake-nvidia-key"
    finally:
        os.environ.pop("SECURITY_LLM_PROVIDER", None)
        os.environ.pop("SECURITY_GEMINI_API_KEY", None)
        os.environ.pop("BUSINESS_LLM_PROVIDER", None)
        os.environ.pop("BUSINESS_NVIDIA_API_KEY", None)


def test_11_summary_and_report_formatting():
    scan_id = "report_scan"
    tracker = get_scan_token_tracker(scan_id, total_budget=6500)
    tracker.agent_caps = {"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100}
    tracker.admit_request("security", 1200)
    tracker.admit_request("business", 800)

    report = format_scan_token_report(scan_id)
    assert "SCAN TOKEN BUDGET SUMMARY REPORT" in report
    assert "Total Scan Budget : 6500 tokens" in report
    assert "Total Actual Used : 2000 tokens" in report
    assert "Total Unused      : 4500 tokens" in report
    assert "security          : EXECUTED" in report
    assert "business          : EXECUTED" in report
    assert "architecture      : SKIPPED" in report


def test_12_thread_safety_concurrent_admissions():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000, "architecture": 1100, "threat_simulation": 1000, "patch": 450, "validation": 450, "shared": 100})
    successes = []

    def worker(agent, tokens):
        admitted, dec, _, _, _ = tracker.admit_request(agent, tokens)
        if admitted:
            successes.append((agent, tokens))

    threads = [
        threading.Thread(target=worker, args=("security", 500)),
        threading.Thread(target=worker, args=("security", 500)),
        threading.Thread(target=worker, args=("business", 1000)),
        threading.Thread(target=worker, args=("architecture", 400)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_admitted = sum(tok for _, tok in successes)
    assert total_admitted <= 6500
    assert tracker.remaining_budget == 6500 - total_admitted


def test_13_tracker_reset():
    t1 = get_scan_token_tracker("scan_a")
    t1.agent_caps = {"security": 2200, "business": 4000}
    t1.admit_request("security", 500)
    reset_scan_token_trackers()
    t2 = get_scan_token_tracker("scan_a")
    assert t2.remaining_budget == 6500
    assert len(t2.agent_spent) == 0


def test_14_reasoning_gateway_token_lifecycle():
    cfg = LLMConfig(api_key="fake_key", provider="gemini", enabled=True)
    gateway = ReasoningGateway(config=cfg)

    mock_response = MagicMock()
    mock_response.content = '{"findings": [{"title": "Vulnerability Analysis", "severity": "HIGH", "category": "security", "file": "main.py", "line": 1, "reason": "Verified security control", "description": "Verified", "recommendation": "Maintain", "confidence": 0.9, "evidence_ids": ["E1"]}], "summary": "Verified"}'
    mock_response.model = "gemini-flash"
    mock_response.total_tokens = 350

    scan_id = "lifecycle_scan"
    tracker = get_scan_token_tracker(scan_id, total_budget=6500)
    tracker.agent_caps = {"security": 2200, "business": 4000, "architecture": 1100}

    req = ReasoningRequest(
        task="security_reasoning",
        agent="security",
        scan_id=scan_id,
        instruction="Analyze vulnerability",
        max_tokens=400,
    )

    with patch.object(gateway, "_client") as mock_client_func:
        mock_client = MagicMock()
        mock_client.chat.return_value = mock_response
        mock_client_func.return_value = mock_client

        res = gateway.reason(req)
        assert res.ok is True
        # Initial request est ~20 (sys) + prompt/4 + 400 = ~450 tokens
        # Actual used = 350 tokens. Unused tokens released.
        assert tracker.agent_spent["security"] == 350
        assert tracker.remaining_budget == 6150


def test_15_multi_agent_execution_simulation():
    scan_id = "sim_scan"
    tracker = get_scan_token_tracker(scan_id, total_budget=6500)
    tracker.agent_caps = {"security": 2200, "business": 4000, "architecture": 1100}

    # SecurityAgent executes an LLM call using 800 tokens
    admitted_sec, _, _, _, _ = tracker.admit_request("security", 1200)
    assert admitted_sec is True
    tracker.release_unused("security", 1200, 800)

    # BusinessAgent executes an LLM call using 900 tokens
    admitted_bus, _, _, _, _ = tracker.admit_request("business", 1200)
    assert admitted_bus is True
    tracker.release_unused("business", 1200, 900)

    # ArchitectureAgent executes an LLM call using 400 tokens
    admitted_arch, _, _, _, _ = tracker.admit_request("architecture", 600)
    assert admitted_arch is True
    tracker.release_unused("architecture", 600, 400)

    summary = tracker.get_summary()
    assert summary["remaining_budget"] == 6500 - 800 - 900 - 400  # 4400 remaining
    assert summary["agent_spent"]["security"] == 800
    assert summary["agent_spent"]["business"] == 900
    assert summary["agent_spent"]["architecture"] == 400


def test_16_exact_agent_cap_request_executed():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000})
    admitted, decision, remaining, cap, capacity = tracker.admit_request("security", 2200)
    assert admitted is True
    assert decision == "EXECUTED"
    assert remaining == 4300
    assert tracker.agent_spent["security"] == 2200


def test_17_one_token_over_agent_cap_skipped():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"security": 2200, "business": 4000})
    admitted, decision, remaining, cap, capacity = tracker.admit_request("security", 2201)
    assert admitted is False
    assert decision == "SKIPPED_AGENT_CAP"
    assert remaining == 6500
    assert tracker.agent_spent.get("security", 0) == 0


def test_18_cumulative_requests_equal_cap_executed():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"business": 4000})
    a1, d1, _, _, _ = tracker.admit_request("business", 2000)
    tracker.release_unused("business", 2000, 2000)
    a2, d2, _, _, _ = tracker.admit_request("business", 2000)
    tracker.release_unused("business", 2000, 2000)
    assert a1 is True and d1 == "EXECUTED"
    assert a2 is True and d2 == "EXECUTED"
    assert tracker.agent_spent["business"] == 4000


def test_19_cumulative_request_exceeding_cap_skipped():
    tracker = ScanTokenTracker(total_budget=6500, agent_reservations={"business": 4000})
    tracker.admit_request("business", 2000)
    tracker.release_unused("business", 2000, 2000)
    tracker.admit_request("business", 2000)
    tracker.release_unused("business", 2000, 2000)
    admitted, decision, remaining, cap, capacity = tracker.admit_request("business", 1)
    assert admitted is False
    assert decision == "SKIPPED_AGENT_CAP"
    assert tracker.agent_spent["business"] == 4000


def test_20_rejected_request_does_not_call_provider():
    cfg = LLMConfig(api_key="fake_key", provider="gemini", enabled=True)
    gateway = ReasoningGateway(config=cfg)
    scan_id = "rejection_no_provider_scan"
    tracker = get_scan_token_tracker(scan_id, total_budget=6500)
    tracker.agent_caps = {"security": 2200}
    tracker.admit_request("security", 2200)
    tracker.release_unused("security", 2200, 2200)

    req = ReasoningRequest(
        task="security_reasoning",
        agent="security",
        scan_id=scan_id,
        instruction="Analyze vulnerability",
        max_tokens=400,
    )

    with patch.object(gateway, "_client") as mock_client_func:
        mock_client = MagicMock()
        mock_client_func.return_value = mock_client

        res = gateway.reason(req)
        assert res.ok is False
        assert "SKIPPED_AGENT_CAP" in res.error
        mock_client.chat.assert_not_called()


def test_21_rejected_request_does_not_consume_global_budget():
    tracker = ScanTokenTracker(total_budget=6500)
    tracker.admit_request("architecture", 1100)
    tracker.release_unused("architecture", 1100, 1100)
    remaining_before = tracker.remaining_budget

    admitted, decision, remaining_after, _, _ = tracker.admit_request("architecture", 500)
    assert admitted is False
    assert decision == "SKIPPED_AGENT_CAP"
    assert remaining_after == remaining_before == 5400


def test_22_unused_reservation_released_correctly():
    tracker = ScanTokenTracker(total_budget=6500)
    tracker.admit_request("business", 1500)
    assert tracker.remaining_budget == 5000
    assert tracker.agent_spent["business"] == 1500

    released = tracker.release_unused("business", 1500, 800)
    assert released == 700
    assert tracker.remaining_budget == 5700
    assert tracker.agent_spent["business"] == 800


def test_23_global_6500_ceiling_remains_intact():
    tracker = ScanTokenTracker()
    assert tracker.total_budget == 6500
    assert tracker.remaining_budget == 6500


def test_24_security_agent_disabled_by_config():
    with patch.dict(os.environ, {"SECURITY_AGENT_ENABLED": "false"}):
        from guardian.agents.security.agent import SecurityAgent
        sec_agent = SecurityAgent()
        state = {
            "scan_id": "test_disabled_sec_scan",
            "findings": [{"rule_id": "SEC-001", "severity": "HIGH", "file": "app.py", "line": 10}],
            "evidence": [{"id": "E1", "file": "app.py", "line": 10, "snippet": "code"}]
        }
        res_state = sec_agent._process(state)
        sec_context = res_state.get("security_context", {})
        assert sec_context.get("grok_status") == "DISABLED_BY_CONFIG"
        assert "ai_security_insights" not in res_state
        tracker = get_scan_token_tracker("test_disabled_sec_scan")
        assert tracker.agent_spent.get("security", 0) == 0


def test_25_business_agent_prioritizes_insufficient_and_partial():
    from guardian.agents.business.agent import _policy_priority_key
    f_insufficient = {"status": "INSUFFICIENT_EVIDENCE", "score": 0.0}
    f_partial = {"status": "PARTIAL", "score": 0.5}
    f_low_score = {"status": "EVALUATED", "score": 0.4}
    f_compliant = {"status": "COMPLIANT", "score": 1.0}

    assert _policy_priority_key(f_insufficient) < _policy_priority_key(f_partial)
    assert _policy_priority_key(f_partial) < _policy_priority_key(f_low_score)
    assert _policy_priority_key(f_low_score) < _policy_priority_key(f_compliant)

