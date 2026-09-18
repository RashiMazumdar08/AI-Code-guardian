"""Anti-hallucination layer tests. No live NVIDIA endpoint required: the point of
this suite is that hallucination control is MECHANICAL, not model-dependent."""
import json
from pathlib import Path

import pytest

from guardian.ai.scan_context import exact_match_context, findings_to_documents
from guardian.ai.validator import ResponseValidator


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    f = tmp_path / "src" / "pay.py"
    f.parent.mkdir()
    f.write_text("\n".join(f"line{i}" for i in range(1, 51)))  # 50 lines
    return tmp_path


@pytest.fixture()
def report() -> dict:
    return {"scan": {"target": "x", "files_scanned": 1, "total_findings": 1,
                     "by_severity": {"High": 1},
                     "findings": [{
                         "finding_id": "abc123def4567890", "rule_id": "RS-SQLI-001",
                         "category": "SQL Injection", "severity": "High",
                         "file": "src/pay.py", "line": 12,
                         "snippet": "format!(\"SELECT ...\")",
                         "recommendation": "Use bind parameters.",
                         "cwe": "CWE-89", "owasp": "A03", "confidence": 0.6}]},
            "risk": {"security_score": 60.0, "overall_risk_score": 70.0,
                     "merge_decision": "Warn"}}


# ---- validator -------------------------------------------------------
def test_validator_catches_fabricated_file(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("The bug is in `src/imaginary_module.py:44` and violates RS-SQLI-001.")
    assert not r.ok
    assert any("imaginary_module" in x for x in r.violations)


def test_validator_catches_impossible_line(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("See src/pay.py:400 for the vulnerable query.")
    assert not r.ok and any("out of range" in x for x in r.violations)


def test_validator_catches_invented_rule(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("This was flagged by rule ACG-MAGIC-999.")
    assert not r.ok and any("ACG-MAGIC-999" in x for x in r.violations)


def test_validator_accepts_true_claims(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("Finding RS-SQLI-001 is at src/pay.py:12; fix with bind parameters.")
    assert r.ok, r.violations
    assert r.checked_refs >= 2


# ---- exact-match grounding ------------------------------------------
def test_exact_match_by_rule_id(report):
    ctx = exact_match_context("Why did RS-SQLI-001 fire?", report)
    assert "RS-SQLI-001" in ctx and "src/pay.py:12" in ctx


def test_exact_match_by_filename(report):
    ctx = exact_match_context("what's wrong in pay.py?", report)
    assert "SQL Injection" in ctx


def test_exact_match_returns_empty_not_guess(report):
    assert exact_match_context("tell me about kubernetes", report) == ""


def test_findings_become_documents(report):
    docs = findings_to_documents(report)
    assert len(docs) == 2  # 1 finding + 1 summary
    assert any("RS-SQLI-001" in d.content for d in docs)
    # The summary document surfaces the plain-English repository security
    # status (guardian.reporting.report_view_model.compute_verdict's label
    # -- "NEEDS ATTENTION" here, since this fixture has a High finding and
    # no criticals), not the raw internal `merge_decision` field: that
    # field is source-control workflow language ("Warn", "Merge Allowed")
    # the chatbot was never asked to reason about, and surfacing it
    # verbatim was itself a source of confusing, ungrounded-sounding
    # answers. See guardian/ai/scan_context.py:findings_to_documents.
    assert any("repository_security_status" in d.content for d in docs)
    assert any("NEEDS ATTENTION" in d.content for d in docs)
    assert not any("merge_decision" in d.content for d in docs)


# ---- general knowledge without evidence, repo claims still refused ---
def test_pipeline_answers_general_question_without_evidence(repo, report, monkeypatch):
    """With nothing indexed, a general-knowledge question should still get
    a real answer from the LLM (marked ungrounded, since it isn't tied to
    repo evidence) rather than a blanket refusal before the model is even
    asked — that blanket refusal was itself a bug: it made the assistant
    unable to answer "what is SQL injection?" whenever no scan was loaded.
    Fabricated REPO-SPECIFIC claims are still caught, but by the
    ResponseValidator after the fact (see test_validator_catches_* above),
    not by refusing to call the LLM at all."""
    from guardian.ai.config import AssistantConfig
    from guardian.ai.rag_pipeline import RAGPipeline
    from guardian.ai.prompt_builder import PromptBuilder
    from guardian.ai.models import RAGResult

    class FakeRetriever:
        def retrieve(self, q):
            return RAGResult(query=q, chunks=[], merged_context="", citations=[])

    class FakeLLM:  # now IS expected to be called
        def chat(self, messages):
            class _Resp:
                content = ("[General Knowledge — not from the indexed repository] "
                          "SQL injection is a vulnerability where untrusted input "
                          "is concatenated into a SQL query instead of bound as a parameter.")
            return _Resp()

    class FakeMemory:
        class _Ctx: repo_summary = ""
        context = _Ctx()
        def get_history(self): return []
        def add_user_message(self, m): pass
        def add_assistant_message(self, m): pass

    cfg = AssistantConfig()
    pipe = RAGPipeline(cfg, FakeLLM(), FakeRetriever(),
                       prompt_builder=PromptBuilder(cfg), memory=FakeMemory())
    resp = pipe.ask("what is SQL injection?")
    assert "SQL injection is a vulnerability" in resp.answer
    assert resp.grounded is False  # honestly not tied to any indexed repo evidence
