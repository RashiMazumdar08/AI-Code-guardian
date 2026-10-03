"""
Regression Test Suite for Simplest SAST Vulnerable Business Rules Document Ingestion
========================================================================================
Verifies:
1. DocumentLoader parses exactly 16 canonical business rules (BR-001 through BR-016).
2. Document metadata (Evidence policy, Repository scope, Business Intent Result Semantics) are NOT parsed as rules.
3. Summary table on Page 1 does not create duplicate rules.
4. Detailed canonical sections are the authoritative source for requirement text, expected evidence, evidence terms, and severity.
5. Detailed verification for BR-001 content.
"""
from __future__ import annotations

from pathlib import Path
import pytest

from guardian.intent.ingestion.document_loader import DocumentLoader, _read_document_text


class TestSimplestSASTDocumentIngestion:
    """Test suite for Simplest SAST PDF ingestion."""

    @pytest.fixture
    def pdf_path(self) -> Path:
        p = Path("data/business_docs/Simplest_SAST_Vulnerable_Business_Rules.pdf")
        if not p.exists():
            p = Path("AI-Code-Guardian-ai_features/data/business_docs/Simplest_SAST_Vulnerable_Business_Rules.pdf")
        assert p.exists(), f"PDF fixture not found at {p}"
        return p

    def test_extract_exact_16_canonical_rules(self, pdf_path: Path):
        loader = DocumentLoader(docs_dir=pdf_path.parent)
        text = _read_document_text(pdf_path)
        lines = text.splitlines()

        reqs = loader._extract_canonical_rule_document(lines, pdf_path.name)
        assert reqs is not None, "Failed to extract canonical rule document"

        # 1. Total parsed rules must equal exactly 16
        assert len(reqs) == 16, f"Expected 16 rules, got {len(reqs)}"

        # 2. Rule IDs must be BR-001 through BR-016
        expected_ids = [f"BR-{i:03d}" for i in range(1, 17)]
        actual_ids = [r.id for r in reqs]
        assert actual_ids == expected_ids, f"Expected rule IDs {expected_ids}, got {actual_ids}"

        # 3. Document-level metadata sections are NOT rules
        rule_texts_and_titles = [f"{r.title} {r.text}".lower() for r in reqs]
        for item in rule_texts_and_titles:
            assert "evidence policy: these are business/security requirements" not in item
            assert "business intent result semantics" not in item
            assert "repository scope" not in item

        # 4. Assert BR-001 exact canonical concepts
        br001 = reqs[0]
        assert br001.id == "BR-001"
        assert br001.title == "Parameterized SQL Queries"
        assert br001.severity == "Critical"
        assert "User-controlled input must never be concatenated directly into SQL statements" in br001.text
        assert "parameterized queries" in br001.expected_implementation_behavior.lower() or "database calls" in br001.expected_implementation_behavior.lower()
        
        # Check evidence terms
        terms_str = " ".join(br001.evidence_terms).lower()
        assert "sql query construction" in terms_str or "sql" in terms_str
        assert "database calls" in terms_str or "database" in terms_str

        # Ensure document-level evidence policy is NOT in BR-001 text
        assert "evidence policy" not in br001.text.lower()

    def test_end_to_end_document_loader_extracts_16(self, pdf_path: Path):
        loader = DocumentLoader(docs_dir=pdf_path.parent)
        reqs = loader.extract_actionable_requirements()
        
        pdf_reqs = [r for r in reqs if r.source == pdf_path.name]
        assert len(pdf_reqs) == 16, f"Expected 16 requirements from PDF, got {len(pdf_reqs)}"
        assert [r.id for r in pdf_reqs] == [f"BR-{i:03d}" for i in range(1, 17)]
