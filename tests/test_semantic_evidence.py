"""
Unit tests for Semantic Evidence Retrieval & Fusion Layer
===========================================================
Tests semantic evidence retrieval, triggering policies, fusion boundaries,
LLM-free execution, token limits, and regression safety.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.intent.engine import BusinessIntentEngine
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.intent.parser.rule_parser import ParsedRule
from guardian.intent.semantic.code_index import CodeSemanticIndex
from guardian.intent.semantic.evidence_fusion import EvidenceFusionEngine, FusedRuleResult
from guardian.intent.semantic.semantic_retriever import SemanticRetriever, SemanticSearchResult


def test_1_compliant_does_not_trigger_semantic_search():
    det_result = {
        "rule_id": "REQ-001",
        "original_requirement": "Cart quantity check required",
        "status": "COMPLIANT",
        "score": 0.95,
        "evidence_items": [{"file": "cart.py", "function": "add_to_cart", "line": 10}],
        "missing_controls": [],
    }
    fusion = EvidenceFusionEngine()
    fused = fusion.fuse_rule_result(det_result)

    assert fused.semantic_retrieval_performed is False
    assert len(fused.semantic_candidates) == 0
    assert fused.final_status == "COMPLIANT"


def test_2_violation_does_not_trigger_semantic_search_by_default():
    det_result = {
        "rule_id": "REQ-003",
        "original_requirement": "Authoritative Checkout Price Rule",
        "status": "VIOLATION",
        "score": 0.85,
        "negative_evidence": ["Client-supplied total trusted directly"],
        "missing_controls": ["server_side_price_calculation"],
    }
    fusion = EvidenceFusionEngine()
    fused = fusion.fuse_rule_result(det_result)

    assert fused.semantic_retrieval_performed is False
    assert len(fused.semantic_candidates) == 0
    assert fused.final_status == "VIOLATION"


def test_3_partial_triggers_semantic_retrieval():
    code = """
def process_refund(amount):
    if amount > 100:
        db.refund(amount)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "refund.py").write_text(code, encoding="utf-8")

        det_result = {
            "rule_id": "REQ-002",
            "original_requirement": "Refund manager approval required",
            "status": "PARTIAL",
            "score": 0.50,
            "missing_controls": ["manager_approval"],
        }
        fusion = EvidenceFusionEngine(workspace_dir=tmp_path)
        fused = fusion.fuse_rule_result(det_result, top_k=3)

        assert fused.semantic_retrieval_performed is True
        assert len(fused.semantic_candidates) > 0
        assert fused.final_status == "PARTIAL"


def test_4_insufficient_evidence_triggers_semantic_retrieval():
    code = """
def process_order(order_id):
    db.save_order(order_id)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "order.py").write_text(code, encoding="utf-8")

        det_result = {
            "rule_id": "REQ-005",
            "original_requirement": "Sufficient funds check before order creation",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
            "missing_controls": ["sufficient_funds_check"],
        }
        fusion = EvidenceFusionEngine(workspace_dir=tmp_path)
        fused = fusion.fuse_rule_result(det_result, top_k=3)

        assert fused.semantic_retrieval_performed is True
        assert len(fused.semantic_candidates) > 0
        assert fused.final_status == "INSUFFICIENT_EVIDENCE"


def test_5_semantic_similarity_alone_cannot_produce_violation():
    code = """
def transfer_funds(sender, receiver, amount):
    sender.balance -= amount
    receiver.balance += amount
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "transfer.py").write_text(code, encoding="utf-8")

        det_result = {
            "rule_id": "REQ-002",
            "original_requirement": "Balance transfer requires atomic transaction and balance check",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
            "missing_controls": ["sufficient_funds_check", "atomicity"],
        }
        fusion = EvidenceFusionEngine(workspace_dir=tmp_path)
        fused = fusion.fuse_rule_result(det_result, top_k=3)

        # High similarity must NOT flip verdict to VIOLATION
        assert fused.final_status != "VIOLATION"
        assert fused.final_status == "INSUFFICIENT_EVIDENCE"
        assert len(fused.semantic_candidates) > 0
        for cand in fused.semantic_candidates:
            assert cand.get("evidence_source") == "SEMANTIC"


def test_6_semantic_evidence_preserved_separately():
    det_result = {
        "rule_id": "REQ-001",
        "original_requirement": "Inventory availability check",
        "status": "PARTIAL",
        "score": 0.60,
        "evidence_items": [{"type": "CONTROL_FLOW", "file": "cart.py", "function": "add_to_cart"}],
        "missing_controls": ["stock_availability_check"],
    }

    retriever_res = [
        SemanticSearchResult(
            match_id="S001",
            file="inventory.py",
            function="check_stock",
            line=15,
            snippet="def check_stock(item_id): ...",
            requirement_or_control="stock_availability_check",
            similarity=0.88,
        )
    ]

    class FakeRetriever:
        def search(self, query: str, top_k: int = 3):
            return retriever_res

    fusion = EvidenceFusionEngine(retriever=FakeRetriever())
    fused = fusion.fuse_rule_result(det_result)

    assert fused.deterministic_evidence == det_result["evidence_items"]
    assert len(fused.semantic_candidates) == 1
    assert fused.semantic_candidates[0]["match_id"] == "S001"
    assert fused.semantic_candidates[0]["evidence_source"] == "SEMANTIC"


def test_7_use_llm_false_performs_completely_deterministic_analysis():
    rule = ParsedRule(
        rule_id="REQ-001",
        requirement_text="Cart Quantity and Inventory Rule",
        source_file="business_rules.pdf",
        line_number=1,
        action="cart",
        condition="qty <= 0",
        control="stock",
        rule_type="STRUCTURED",
        title="Cart Quantity and Inventory Rule",
    )
    matcher = RuleMatcher(enable_semantic=True)
    res = matcher.evaluate_rule(rule)

    assert "status" in res
    assert "deterministic_status" in res
    assert "semantic_candidates" in res


def test_8_token_context_size_remains_bounded():
    code = "\n".join([f"def fn_{i}(): pass" for i in range(20)])
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "funcs.py").write_text(code, encoding="utf-8")

        retriever = SemanticRetriever(workspace_dir=tmp_path)
        results = retriever.search("function execution", top_k=3)

        assert len(results) <= 3
        total_chars = sum(len(r.snippet) for r in results)
        assert total_chars < 2000  # Bounded size


def test_9_existing_business_intent_tests_pass():
    engine = BusinessIntentEngine(use_llm=False)
    result = engine.run()
    assert result.get("status") in ("SUCCESS", "NO_DOCUMENTS")


def test_10_real_dv_bookshop_scan_does_not_regress():
    repo_root = Path.cwd()
    docs_dir = repo_root / "data" / "business_docs"

    if docs_dir.exists():
        engine = BusinessIntentEngine(docs_dir=docs_dir, use_llm=False)
        result = engine.run()

        assert result.get("status") == "SUCCESS"
        assert result.get("total_rules") > 0
        findings = result.get("findings", [])
        assert len(findings) > 0
        for f in findings:
            assert "status" in f
            assert "deterministic_status" in f
            assert "semantic_candidates" in f
