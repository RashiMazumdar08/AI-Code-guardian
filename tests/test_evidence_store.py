"""Shared evidence model + store tests."""
from __future__ import annotations

import pytest

from guardian.evidence import Evidence, EvidenceStore, EvidenceType, FindingSource
from guardian.evidence.models import ValidatedFinding


def _evidence(**kwargs) -> Evidence:
    defaults = dict(
        type=EvidenceType.CRYPTO_USAGE,
        source="ust_crypto_detector",
        file="PaymentService.java",
        line=84,
        language="java",
        symbol="encryptPayment",
        operation="RSA encryption",
    )
    defaults.update(kwargs)
    return Evidence(**defaults)


class TestEvidenceModel:
    def test_fingerprint_is_stable_and_content_derived(self):
        assert _evidence().fingerprint == _evidence().fingerprint
        assert _evidence().fingerprint != _evidence(line=85).fingerprint

    def test_string_type_is_coerced_to_enum(self):
        e = Evidence(type="crypto_usage", source="x")
        assert e.type is EvidenceType.CRYPTO_USAGE

    def test_unknown_type_falls_back_to_other(self):
        e = Evidence(type="not_a_real_type", source="x")
        assert e.type is EvidenceType.OTHER

    def test_context_line_omits_raw_source(self):
        e = _evidence(snippet="Cipher.getInstance(\"RSA\")  // secret=hunter2")
        e.id = "E102"
        line = e.to_context_line()
        assert "E102" in line and "RSA encryption" in line
        assert "PaymentService.java:84" in line
        assert "hunter2" not in line, "snippets must not leak into prompt context"

    def test_to_dict_round_trips_enum(self):
        d = _evidence().to_dict()
        assert d["type"] == "crypto_usage"
        assert d["operation"] == "RSA encryption"


class TestEvidenceStore:
    def test_ids_are_sequential_and_stable(self):
        store = EvidenceStore()
        a = store.add(_evidence(line=1))
        b = store.add(_evidence(line=2))
        assert a.id == "E1" and b.id == "E2"
        assert store.get("E1") is a

    def test_duplicate_publication_dedupes_to_the_same_id(self):
        store = EvidenceStore()
        first = store.add(_evidence())
        second = store.add(_evidence())
        assert first.id == second.id
        assert len(store) == 1

    def test_resolve_reports_unknown_ids(self):
        """This is what stops an LLM inventing evidence."""
        store = EvidenceStore()
        store.add(_evidence())
        found, missing = store.resolve(["E1", "E999", "not-an-id"])
        assert [e.id for e in found] == ["E1"]
        assert missing == ["E999", "not-an-id"]

    def test_exists(self):
        store = EvidenceStore()
        store.add(_evidence())
        assert store.exists("E1")
        assert not store.exists("E2")

    def test_indexes_by_type_file_and_source(self):
        store = EvidenceStore()
        store.add(_evidence())
        store.add(_evidence(type=EvidenceType.SECRET, source="secret_scanner",
                            file="config.py", line=3, operation="hardcoded key"))
        assert len(store.by_type(EvidenceType.CRYPTO_USAGE)) == 1
        assert len(store.by_file("config.py")) == 1
        assert len(store.by_source("secret_scanner")) == 1

    def test_search_filters_and_limits(self):
        store = EvidenceStore()
        for i in range(5):
            store.add(_evidence(line=i, confidence=0.5 + i / 10))
        store.add(_evidence(type=EvidenceType.SECRET, source="secret_scanner",
                            file="c.py", line=1))

        crypto = store.search(types=[EvidenceType.CRYPTO_USAGE])
        assert len(crypto) == 5
        assert crypto[0].confidence >= crypto[-1].confidence, "sorted by confidence"

        assert len(store.search(types=[EvidenceType.CRYPTO_USAGE], limit=2)) == 2
        # confidences 0.5..0.9 for the crypto items, plus the default-1.0 secret
        assert len(store.search(min_confidence=0.8)) == 3
        assert len(store.search(files=["c.py"])) == 1

    def test_search_by_tag(self):
        store = EvidenceStore()
        store.add(_evidence(tags=["quantum_vulnerable"]))
        store.add(_evidence(line=99, tags=["pqc"]))
        assert len(store.search(tags=["quantum_vulnerable"])) == 1

    def test_summary(self):
        store = EvidenceStore()
        store.add(_evidence())
        store.add(_evidence(type=EvidenceType.SECRET, source="secret_scanner", line=7))
        summary = store.summary()
        assert summary["total"] == 2
        assert summary["by_type"]["crypto_usage"] == 1
        assert summary["by_source"]["secret_scanner"] == 1

    def test_empty_store_is_usable(self):
        store = EvidenceStore()
        assert len(store) == 0
        assert store.search() == []
        assert store.resolve(["E1"]) == ([], ["E1"])
        assert store.summary()["total"] == 0


class TestValidatedFinding:
    def test_insufficient_evidence_is_not_accepted(self):
        vf = ValidatedFinding(category="quantum_readiness", severity="High",
                              confidence=0.9, reason="r", recommendation="x",
                              source=FindingSource.INSUFFICIENT_EVIDENCE)
        assert not vf.accepted

    def test_validated_and_suggested_are_accepted(self):
        for source in (FindingSource.AI_VALIDATED, FindingSource.AI_SUGGESTED):
            vf = ValidatedFinding(category="c", severity="High", confidence=0.9,
                                  reason="r", recommendation="x", source=source)
            assert vf.accepted

    def test_to_dict_serialises_source(self):
        vf = ValidatedFinding(category="c", severity="High", confidence=0.9,
                              reason="r", recommendation="x",
                              source=FindingSource.AI_VALIDATED,
                              evidence_ids=["E1"])
        d = vf.to_dict()
        assert d["source"] == "AI_VALIDATED"
        assert d["evidence_ids"] == ["E1"]


class TestFindingProvenanceFields:
    def test_existing_construction_still_works(self):
        """Backward compatibility: the pre-refactor call shape is untouched."""
        from guardian.core.models import Finding
        f = Finding(category="SQL Injection", severity="High", rule_id="X",
                    file="a.py", line=1, snippet="s", recommendation="r")
        assert f.finding_id
        assert f.source == "DETERMINISTIC"
        assert f.evidence_ids == []
        assert not f.is_ai

    def test_new_fields_serialise(self):
        from guardian.core.models import Finding
        f = Finding(category="c", severity="High", rule_id="X", file="a.py",
                    line=1, snippet="s", recommendation="r",
                    language="python", function="process_refund",
                    evidence_ids=["E1", "E2"], source="AI_VALIDATED",
                    reason="because", engine="business_intent")
        d = f.to_dict()
        assert d["evidence_ids"] == ["E1", "E2"]
        assert d["source"] == "AI_VALIDATED"
        assert d["function"] == "process_refund"
        assert f.is_ai
