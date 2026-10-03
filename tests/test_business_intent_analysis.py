"""
Unit tests for Deterministic Business Evidence Analyzer
=========================================================
Tests AST control-flow, data-flow, inter-procedural analysis,
and specialized business detectors for REQ-001 through REQ-005.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.intent.analysis.business_evidence import (
    BusinessEvidenceAnalyzer,
    BusinessEvidenceItem,
    DeterministicRuleAnalysis,
    EvidenceType,
)
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.intent.parser.rule_parser import ParsedRule


def test_req_001_cart_quantity_inventory_compliant():
    cart_code = """
def add_to_cart(cart, book_id, quantity):
    if quantity <= 0:
        raise ValueError("Invalid quantity")
    book = get_book(book_id)
    if book.stock < quantity:
        raise OutOfStockError("Not enough inventory")
    cart.add(book_id, quantity)
    return cart
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cart_file = tmp_path / "cart.py"
        cart_file.write_text(cart_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-001", "Cart quantity and inventory rule")

        assert analysis.deterministic_verdict == "COMPLIANT"
        assert analysis.confidence >= 0.90
        assert "cart.py" in analysis.matched_file
        assert analysis.matched_function == "add_to_cart"
        assert len(analysis.all_evidence()) >= 1


def test_req_002_balance_transfer_missing_atomicity():
    balance_code = """
def transfer_balance(sender, receiver, amount):
    if sender.balance < amount:
        raise InsufficientFunds()
    sender.balance -= amount
    receiver.balance += amount
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pay_file = tmp_path / "payment.py"
        pay_file.write_text(balance_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-002", "Balance Transfer Integrity Rule")

        # Missing atomicity transaction control
        assert "atomicity" in analysis.missing_controls
        assert analysis.deterministic_verdict in ("PARTIAL", "INSUFFICIENT_EVIDENCE")


def test_req_002_balance_transfer_with_transaction():
    atomic_code = """
@transactional
def transfer_balance(sender, receiver, amount):
    if sender.balance < amount:
        raise InsufficientFunds()
    sender.balance -= amount
    receiver.balance += amount
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pay_file = tmp_path / "payment.py"
        pay_file.write_text(atomic_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-002", "Balance Transfer Integrity Rule")

        assert analysis.deterministic_verdict == "COMPLIANT"
        assert "atomicity" not in analysis.missing_controls


def test_req_003_authoritative_checkout_price_compliant():
    checkout_code = """
def checkout(user_id, cart_items):
    total = 0
    for item in cart_items:
        book = db.get_book(item.id)
        total += book.price * item.quantity
    charge_user(user_id, total)
    return total
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        co_file = tmp_path / "checkout.py"
        co_file.write_text(checkout_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-003", "Authoritative Checkout Price Rule")

        assert analysis.deterministic_verdict == "COMPLIANT"
        assert analysis.confidence >= 0.85
        assert "checkout.py" in analysis.matched_file


def test_req_003_authoritative_checkout_price_violation():
    flawed_checkout_code = """
def checkout(request_data):
    # Vulnerable: uses client-supplied total directly
    client_total = request_data.get("total")
    charge_user(user_id, client_total)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        co_file = tmp_path / "checkout.py"
        co_file.write_text(flawed_checkout_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-003", "Authoritative Checkout Price Rule")

        assert analysis.deterministic_verdict == "VIOLATION"
        assert len(analysis.negative_evidence) > 0


def test_req_004_coupon_usage_limit_compliant():
    coupon_code = """
def apply_coupon(coupon_code):
    coupon = get_coupon(coupon_code)
    if not coupon.is_active:
        raise CouponExpired()
    if coupon.used_count >= coupon.max_uses:
        raise CouponLimitExceeded()
    coupon.used_count += 1
    return coupon.discount
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cp_file = tmp_path / "coupons.py"
        cp_file.write_text(coupon_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-004", "Coupon Usage Limit and Active Check")

        assert analysis.deterministic_verdict == "COMPLIANT"
        assert "coupons.py" in analysis.matched_file


def test_req_005_sufficient_funds_compliant():
    funds_code = """
def process_order(user_id, order_id):
    total = calculate_order_total(order_id)
    user = get_user(user_id)
    if user.balance < total:
        raise InsufficientFundsError()
    user.balance -= total
    pay_gateway.charge(user_id, total)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pf_file = tmp_path / "payment.py"
        pf_file.write_text(funds_code, encoding="utf-8")

        analyzer = BusinessEvidenceAnalyzer(workspace_dir=tmp_path)
        analysis = analyzer.analyze_rule("REQ-005", "Sufficient Funds for Authoritative Total")

        assert analysis.deterministic_verdict == "COMPLIANT"
        assert "payment.py" in analysis.matched_file


def test_rule_matcher_integration_llm_free():
    cart_code = """
def add_to_cart(cart, book_id, quantity):
    if quantity <= 0:
        raise ValueError("Invalid quantity")
    book = get_book(book_id)
    if book.stock < quantity:
        raise OutOfStockError("Not enough inventory")
    cart.add(book_id, quantity)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cart_file = tmp_path / "cart.py"
        cart_file.write_text(cart_code, encoding="utf-8")

        rule = ParsedRule(
            rule_id="REQ-001",
            requirement_text="Cart Quantity and Inventory Rule: Positive quantity and stock availability required",
            source_file="business_rules.pdf",
            line_number=1,
            action="cart",
            condition="qty <= 0",
            control="stock",
            rule_type="STRUCTURED",
            title="Cart Quantity and Inventory Rule",
        )

        matcher = RuleMatcher(workspace_dir=tmp_path)
        eval_res = matcher.evaluate_rule(rule)

        assert eval_res["status"] == "COMPLIANT"
        assert eval_res["matched_file"] == "cart.py"
        assert eval_res["matched_function"] == "add_to_cart"
        assert len(eval_res["evidence_items"]) > 0


def test_business_agent_eligibility_insufficient_evidence_only(monkeypatch):
    """Verify BusinessAgent is invoked ONLY for INSUFFICIENT_EVIDENCE, not for PARTIAL, COMPLIANT, or VIOLATION."""
    from guardian.agents.business.agent import BusinessAgent
    import json

    monkeypatch.setenv("GEMINI_API_KEY", "dummy_gemini_key")
    monkeypatch.setenv("BUSINESS_API_KEY", "dummy_business_key")
    captured_requests = []

    fake_response_json = json.dumps({
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
            "extras": {
                "verdict": "VIOLATION",
                "policy_id": "REQ-002"
            }
        }]
    })

    class MockGateway:
        def __init__(self, config):
            self.configured = True

        def reason(self, req):
            captured_requests.append(req)
            from guardian.reasoning.schemas import parse_reasoning_response
            parsed = parse_reasoning_response(fake_response_json, task="business_intent", model="gemini-3.5-flash-lite")
            from guardian.reasoning.gateway import ReasoningResult
            return ReasoningResult(response=parsed, available=True)

    monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

    # 1. Test PARTIAL finding -> BusinessAgent MUST NOT call ReasoningGateway
    state_partial = {
        "scan_id": "test_partial_eligibility",
        "business_intent_results": {
            "status": "SUCCESS",
            "documents": ["rules.txt"],
            "total_rules": 1,
            "findings": [
                {
                    "rule_id": "REQ-001",
                    "status": "PARTIAL",
                    "score": 0.5,
                    "rule": "Partial policy requirement",
                    "matched_file": "payment.py"
                }
            ]
        }
    }
    agent = BusinessAgent()
    res_partial = agent._process(state_partial)

    assert len(captured_requests) == 0, "PARTIAL must NOT trigger Gemini/ReasoningGateway calls"
    assert "ai_business_insights" not in res_partial or len(res_partial.get("ai_business_insights", [])) == 0, "PARTIAL must NOT produce ai_business_insights"
    assert res_partial["business_intent_results"]["grok_status"] == "SKIPPED"

    # 2. Test COMPLIANT and VIOLATION findings -> MUST NOT call ReasoningGateway
    state_compliant_violation = {
        "scan_id": "test_comp_viol_eligibility",
        "business_intent_results": {
            "status": "SUCCESS",
            "documents": ["rules.txt"],
            "total_rules": 2,
            "findings": [
                {"rule_id": "REQ-003", "status": "COMPLIANT", "score": 1.0},
                {"rule_id": "REQ-004", "status": "VIOLATION", "score": 0.0}
            ]
        }
    }
    res_comp_viol = agent._process(state_compliant_violation)
    assert len(captured_requests) == 0, "COMPLIANT and VIOLATION must NOT trigger Gemini"

    # 3. Test INSUFFICIENT_EVIDENCE finding -> BusinessAgent MUST call ReasoningGateway
    state_insufficient = {
        "scan_id": "test_insufficient_eligibility",
        "business_intent_results": {
            "status": "SUCCESS",
            "documents": ["rules.txt"],
            "total_rules": 1,
            "findings": [
                {
                    "rule_id": "REQ-002",
                    "status": "INSUFFICIENT_EVIDENCE",
                    "score": 0.0,
                    "rule": "Balance transfer requires atomicity",
                    "matched_file": "payment.py"
                }
            ]
        }
    }
    res_insufficient = agent._process(state_insufficient)
    assert len(captured_requests) == 1, "INSUFFICIENT_EVIDENCE MUST trigger Gemini reasoning"
    assert res_insufficient["business_intent_results"]["grok_status"] == "COMPLETED"
    assert "ai_business_insights" in res_insufficient
    assert len(res_insufficient["ai_business_insights"]) == 1
    assert res_insufficient["ai_business_insights"][0]["policy_id"] == "REQ-002"
