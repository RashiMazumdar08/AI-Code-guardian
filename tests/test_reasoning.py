"""
Reasoning layer tests — structured parsing, the Nemotron gateway,
RAG knowledge retrieval, and AI evidence/hallucination validation.

A fake LLM is injected throughout: these tests assert the platform's
handling of model output, which must be deterministic and offline.
"""
from __future__ import annotations

import json

import pytest

from guardian.config import GuardianConfig
from guardian.core.context import AnalysisContext, RepositoryContext
from guardian.evidence.models import Evidence, EvidenceType, FindingSource
from guardian.llm.base import BaseLLM, LLMAuthError, LLMError, LLMResponse
from guardian.reasoning.gateway import NemotronReasoningService, ReasoningRequest
from guardian.reasoning.knowledge import (
    BuiltinKnowledgeBase, KnowledgeRetriever, query_terms_for,
)
from guardian.reasoning.schemas import (
    ComplianceVerdict, extract_json, parse_business_intent_response,
    parse_quantum_context_response, parse_reasoning_response,
)
from guardian.reasoning.validation import AIFindingValidator, to_findings
from guardian.ust import USTBuilder


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeLLM(BaseLLM):
    """Scripted model. Records what it was sent."""

    def __init__(self, reply: str = "{}", *, error: Exception | None = None):
        self.reply = reply
        self.error = error
        self.prompts: list[str] = []
        self.calls = 0

    @property
    def model_name(self) -> str:
        return "fake/nemotron-test"

    def chat(self, messages, *, temperature=None, max_tokens=None) -> LLMResponse:
        self.calls += 1
        self.prompts.append(messages[-1]["content"])
        if self.error is not None:
            raise self.error
        return LLMResponse(content=self.reply, model=self.model_name)

    def chat_stream(self, messages, *, temperature=None, max_tokens=None):
        yield self.reply

    def is_healthy(self) -> bool:
        return self.error is None


def make_context(tmp_path, files: dict[str, str]) -> AnalysisContext:
    paths = []
    for name, content in files.items():
        p = tmp_path / name
        p.write_text(content)
        paths.append(p)
    repo = RepositoryContext(root=tmp_path, source_files=paths)
    ctx = AnalysisContext(repository=repo, config=GuardianConfig())
    ctx.ust = USTBuilder().build_repository(tmp_path, paths)
    return ctx


def valid_response(**overrides) -> str:
    finding = {
        "evidence_ids": ["E1"], "category": "quantum_readiness", "severity": "High",
        "confidence": 0.9, "reason": "RSA protects long-lived payment data.",
        "recommendation": "Adopt hybrid ML-KEM key establishment.",
        "file": "PaymentService.java", "line": 5, "function": "encryptPayment",
    }
    finding.update(overrides)
    return json.dumps({"summary": "s", "findings": [finding]})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class TestJSONExtraction:
    def test_plain_json(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_markdown_fenced(self):
        assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_json_with_surrounding_prose(self):
        assert extract_json('Here you go:\n{"a": 1}\nHope that helps.') == {"a": 1}

    def test_trailing_commas_and_smart_quotes(self):
        assert extract_json('{“a”: 1,}') == {"a": 1}

    def test_bare_array_is_wrapped_as_findings(self):
        assert extract_json('[{"x": 1}]') == {"findings": [{"x": 1}]}

    def test_no_json(self):
        assert extract_json("I cannot help with that.") is None
        assert extract_json("") is None


class TestReasoningSchema:
    def test_valid_response_parses(self):
        response = parse_reasoning_response(valid_response())
        assert response.ok
        assert response.findings[0].evidence_ids == ["E1"]
        assert response.findings[0].confidence == 0.9

    def test_finding_without_evidence_is_dropped(self):
        """The load-bearing rule: no citation, no finding."""
        response = parse_reasoning_response(json.dumps({"findings": [
            {"category": "c", "severity": "High", "confidence": 0.9, "reason": "r"}]}))
        assert response.findings == []
        assert any("cites no evidence" in p for p in response.problems)

    def test_prose_response_is_rejected(self):
        response = parse_reasoning_response("The code looks insecure to me.")
        assert not response.ok
        assert response.findings == []

    def test_percentage_confidence_is_normalised(self):
        response = parse_reasoning_response(valid_response(confidence=85))
        assert response.findings[0].confidence == 0.85

    def test_word_confidence_is_normalised(self):
        response = parse_reasoning_response(valid_response(confidence="high"))
        assert response.findings[0].confidence == 0.85

    def test_invalid_severity_is_reported_and_defaulted(self):
        response = parse_reasoning_response(valid_response(severity="Catastrophic"))
        assert any("severity invalid" in p for p in response.problems)
        assert response.findings[0].severity == "Info"

    def test_evidence_ids_as_string(self):
        response = parse_reasoning_response(valid_response(evidence_ids="E1, E2"))
        assert response.findings[0].evidence_ids == ["E1", "E2"]

    def test_missing_findings_key_is_a_problem(self):
        response = parse_reasoning_response('{"summary": "all good"}')
        assert any("missing required field" in p for p in response.problems)


class TestTaskSchemas:
    def test_business_intent_verdict_normalised(self):
        response = parse_business_intent_response(json.dumps({"findings": [{
            "evidence_ids": ["E1"], "reason": "r", "severity": "High",
            "confidence": 0.8, "verdict": "violation"}]}))
        assert response.findings[0].extras["verdict"] == ComplianceVerdict.VIOLATION.value

    def test_unknown_verdict_downgrades_to_insufficient(self):
        response = parse_business_intent_response(json.dumps({"findings": [{
            "evidence_ids": ["E1"], "reason": "r", "severity": "High",
            "confidence": 0.8, "verdict": "definitely broken"}]}))
        assert response.findings[0].extras["verdict"] == \
            ComplianceVerdict.INSUFFICIENT_EVIDENCE.value
        assert any("verdict invalid" in p for p in response.problems)

    def test_quantum_migration_urgency_normalised(self):
        response = parse_quantum_context_response(json.dumps({"findings": [{
            "evidence_ids": ["E1"], "reason": "r", "severity": "High",
            "confidence": 0.8, "migration_urgency": "immediate"}]}))
        assert response.findings[0].extras["migration_urgency"] == "IMMEDIATE"


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------
class TestGateway:
    def test_unconfigured_service_degrades_gracefully(self):
        service = NemotronReasoningService(llm=None)
        service._config.api_key = ""
        result = service.reason(ReasoningRequest(task="t", instruction="i",
                                                 schema_instruction="s"))
        assert not result.available
        assert "NVIDIA_API_KEY" in result.error
        assert result.findings == []

    def test_successful_call_returns_parsed_findings(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm)
        result = service.reason(ReasoningRequest(
            task="quantum_readiness", instruction="assess",
            schema_instruction="schema", evidence_block="- E1: crypto_usage"))
        assert result.available and result.ok
        assert result.findings[0].evidence_ids == ["E1"]

    def test_llm_error_does_not_raise(self):
        service = NemotronReasoningService(llm=FakeLLM(error=LLMError("upstream 503")))
        result = service.reason(ReasoningRequest(task="t", instruction="i",
                                                 schema_instruction="s"))
        assert not result.available
        assert "503" in result.error
        assert result.findings == []

    def test_auth_error_is_handled_and_remembered(self):
        service = NemotronReasoningService(llm=FakeLLM(error=LLMAuthError("bad key")))
        result = service.reason(ReasoningRequest(task="t", instruction="i",
                                                 schema_instruction="s"))
        assert not result.available
        assert "authentication" in service.unavailable_reason().lower()

    def test_unexpected_exception_is_contained(self):
        service = NemotronReasoningService(llm=FakeLLM(error=RuntimeError("boom")))
        result = service.reason(ReasoningRequest(task="t", instruction="i",
                                                 schema_instruction="s"))
        assert not result.available and "boom" in result.error

    def test_responses_are_cached(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm)
        request = ReasoningRequest(task="t", instruction="i", schema_instruction="s",
                                    evidence_block="- E1")
        first = service.reason(request)
        second = service.reason(request)
        assert llm.calls == 1
        assert not first.cached and second.cached

    def test_prompt_never_contains_the_whole_repository(self, tmp_path):
        """The structural guarantee: the gateway only sees what it is given."""
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm)
        service.reason(ReasoningRequest(
            task="t", instruction="assess", schema_instruction="schema",
            evidence_block="- E1: crypto_usage | RSA encryption at A.java:5"))
        prompt = llm.prompts[0]
        assert "E1" in prompt
        assert len(prompt) < 4000

    def test_oversized_context_is_truncated_not_dropped_silently(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm, context_budget=1500)
        result = service.reason(ReasoningRequest(
            task="t", instruction="assess", schema_instruction="schema",
            evidence_block="- E1: crypto_usage",
            knowledge_block="K" * 5000, code_snippet="C" * 5000))
        assert result.truncated_sections, "dropped sections must be reported"
        assert len(llm.prompts[0]) <= 1500 + 200

    def test_evidence_survives_truncation(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm, context_budget=1200)
        service.reason(ReasoningRequest(
            task="t", instruction="assess", schema_instruction="schema",
            evidence_block="- E1: the evidence that matters",
            knowledge_block="K" * 8000))
        assert "E1" in llm.prompts[0], "evidence must never be the first thing dropped"

    def test_secrets_are_redacted_before_transmission(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm)
        result = service.reason(ReasoningRequest(
            task="t", instruction="assess", schema_instruction="schema",
            evidence_block="- E1: found AKIAIOSFODNN7EXAMPLE in config"))
        assert "AKIAIOSFODNN7EXAMPLE" not in llm.prompts[0]
        assert result.redactions >= 1

    def test_health_performs_no_network_call(self):
        llm = FakeLLM(valid_response())
        service = NemotronReasoningService(llm=llm)
        health = service.health()
        assert health["configured"] is True
        assert llm.calls == 0


# ---------------------------------------------------------------------------
# Knowledge / RAG
# ---------------------------------------------------------------------------
class TestKnowledgeRetrieval:
    def test_builtin_pack_loads(self):
        assert len(BuiltinKnowledgeBase().entries) > 10

    @pytest.mark.parametrize("terms,expected", [
        (["sql injection"], "OWASP-A03-SQLI"),
        (["md5", "hashing"], "OWASP-A02-CRYPTO"),
        (["ml-kem"], "FIPS-203-MLKEM"),
        (["authorization", "approval"], "BIZ-AUTHZ-CONTROLS"),
    ])
    def test_topic_retrieval(self, terms, expected):
        ids = [s.id for s in BuiltinKnowledgeBase().search(terms)]
        assert expected in ids

    def test_short_term_does_not_match_inside_words(self):
        """'rsa' must not retrieve path-traversal guidance via 'traversal'."""
        ids = [s.id for s in BuiltinKnowledgeBase().search(["rsa"])]
        assert "CWE-22-PATH" not in ids

    def test_retrieval_is_driven_by_evidence_not_phrasing(self):
        crypto = Evidence(type=EvidenceType.CRYPTO_USAGE, source="x",
                          file="A.java", line=5, operation="RSA encryption",
                          tags=["crypto", "quantum_vulnerable"],
                          metadata={"algorithm": "RSA"})
        terms = query_terms_for([crypto])
        assert "post-quantum" in terms and "rsa" in terms
        result = KnowledgeRetriever().retrieve_for_evidence([crypto])
        assert "NIST-PQC-MIGRATION" in [s.id for s in result.snippets]

    def test_rag_failure_falls_back_to_builtin(self):
        class BrokenRetriever:
            def retrieve(self, query):
                raise RuntimeError("faiss index corrupt")

        retriever = KnowledgeRetriever(vector_retriever=BrokenRetriever())
        result = retriever.retrieve(["sql injection"])
        assert result.backend == "builtin"
        assert "faiss index corrupt" in result.error
        assert result.snippets, "a RAG outage must not lose knowledge entirely"

    def test_empty_query_returns_nothing_without_error(self):
        assert KnowledgeRetriever().retrieve([]).snippets == []

    def test_result_render_is_bounded(self):
        result = KnowledgeRetriever().retrieve(["cryptography", "rsa", "injection"])
        assert len(result.render()) < 8000


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
@pytest.fixture
def validation_context(tmp_path):
    ctx = make_context(tmp_path, {"PaymentService.java": (
        "public class PaymentService {\n"
        "  public byte[] encryptPayment(String amount) throws Exception {\n"
        "    Cipher c = Cipher.getInstance(\"RSA\");\n"
        "    return c.doFinal(amount.getBytes());\n"
        "  }\n"
        "}\n")})
    ctx.evidence.add(Evidence(
        type=EvidenceType.CRYPTO_USAGE, source="ust_crypto_detector",
        file="PaymentService.java", line=3, language="java",
        symbol="encryptPayment", operation="RSA encryption",
        metadata={"algorithm": "RSA"}))
    return ctx


class TestAIValidation:
    def _validate(self, ctx, allowed=("E1",), **overrides):
        fields = {"file": "PaymentService.java", "line": 3,
                  "function": "encryptPayment"}
        fields.update(overrides)
        response = parse_reasoning_response(valid_response(**fields))
        return AIFindingValidator(ctx, allowed_evidence=allowed).validate_response(response)

    def test_grounded_claim_is_validated(self, validation_context):
        report = self._validate(validation_context)
        assert len(report.validated) == 1
        assert report.validated[0].source is FindingSource.AI_VALIDATED

    def test_ai_confidence_is_capped_below_deterministic(self, validation_context):
        report = self._validate(validation_context, confidence=1.0)
        assert report.accepted[0].confidence <= 0.9

    def test_fabricated_evidence_id_is_rejected(self, validation_context):
        report = self._validate(validation_context, evidence_ids=["E999"])
        assert report.accepted == []
        assert len(report.rejected) == 1
        assert report.rejected[0].source is FindingSource.INSUFFICIENT_EVIDENCE
        assert "non-existent evidence" in report.rejected[0].validation_notes[0]

    def test_nonexistent_file_is_rejected(self, validation_context):
        report = self._validate(validation_context, file="NotReal.java")
        assert report.accepted == [] or report.suggested
        notes = " ".join((report.rejected + report.accepted)[0].validation_notes)
        assert "not in the scanned repository" in notes

    def test_nonexistent_function_downgrades(self, validation_context):
        report = self._validate(validation_context, function="doesNotExist")
        assert not report.validated
        assert report.suggested or report.rejected

    def test_impossible_line_downgrades(self, validation_context):
        report = self._validate(validation_context, line=9999)
        assert not report.validated

    def test_evidence_not_supplied_for_the_task_downgrades(self, validation_context):
        """Citing a real ID that was never sent means the model guessed."""
        validation_context.evidence.add(Evidence(
            type=EvidenceType.SECRET, source="s", file="other.py", line=1))
        report = self._validate(validation_context, evidence_ids=["E2"], allowed=("E1",))
        assert not report.validated

    def test_hedged_reasoning_becomes_a_suggestion(self, validation_context):
        report = self._validate(
            validation_context,
            reason="This might possibly be a problem for payment data.")
        assert report.suggested and not report.validated
        assert report.suggested[0].confidence <= 0.6

    def test_invented_algorithm_recommendation_is_rejected(self, validation_context):
        response = parse_quantum_context_response(json.dumps({"findings": [{
            "evidence_ids": ["E1"], "severity": "High", "confidence": 0.9,
            "reason": "RSA is quantum vulnerable.",
            "recommendation": "Migrate.",
            "recommended_pqc_algorithm": "QuantumShield-9000",
            "file": "PaymentService.java", "line": 3}]}))
        report = AIFindingValidator(
            validation_context, allowed_evidence={"E1"}).validate_response(response)
        assert report.accepted == []
        assert "unsupported algorithm" in report.rejected[0].validation_notes[-1]

    def test_real_pqc_algorithm_recommendation_is_accepted(self, validation_context):
        response = parse_quantum_context_response(json.dumps({"findings": [{
            "evidence_ids": ["E1"], "severity": "High", "confidence": 0.9,
            "reason": "RSA protects payment data.", "recommendation": "Migrate.",
            "recommended_pqc_algorithm": "ML-KEM-768",
            "file": "PaymentService.java", "line": 3}]}))
        report = AIFindingValidator(
            validation_context, allowed_evidence={"E1"}).validate_response(response)
        assert report.accepted

    def test_algorithm_absent_from_evidence_is_rejected(self, validation_context):
        report = self._validate(
            validation_context,
            reason="The ECDSA signature here is quantum vulnerable.")
        assert report.accepted == []
        assert any("absent from the cited evidence" in n
                   for n in report.rejected[0].validation_notes)

    def test_missing_control_claim_needs_behavioural_evidence(self, validation_context):
        report = self._validate(
            validation_context,
            reason="There is no authorization check before the refund.")
        assert report.accepted == []
        assert any("without behavioural evidence" in n
                   for n in report.rejected[0].validation_notes)

    def test_rejections_are_recorded_for_audit(self, validation_context):
        report = self._validate(validation_context, evidence_ids=["E404"])
        audit = report.to_dict()
        assert audit["rejected"] == 1
        assert audit["rejections"][0]["evidence_ids"] == ["E404"]

    def test_to_findings_marks_provenance(self, validation_context):
        report = self._validate(validation_context)
        findings = to_findings(report.accepted, engine="quantum")
        assert findings[0].source == "AI_VALIDATED"
        assert findings[0].evidence_ids == ["E1"]
        assert findings[0].is_ai

    def test_rejected_claims_never_become_findings(self, validation_context):
        report = self._validate(validation_context, evidence_ids=["E999"])
        assert to_findings(report.rejected, engine="quantum") == []


class TestCentralisedIntegrations:
    """Modules that used to build their own broken LLM clients."""

    def test_verifier_imports_and_is_a_noop_without_a_key(self, tmp_path):
        """Regression: this module raised on import (LLMGuardrails, llm.complete)."""
        from guardian.core.models import Finding
        from guardian.llm.verifier import AIFindingVerifier

        service = NemotronReasoningService(llm=None)
        service._config.api_key = ""
        finding = Finding(category="SQL Injection", severity="High", rule_id="X",
                          file="a.py", line=1, snippet="s", recommendation="r")
        out = AIFindingVerifier(service=service).verify_findings(tmp_path, [finding])
        assert out == [finding]
        assert out[0].recommendation == "r", "no annotation without a model"

    def test_verifier_demotes_rather_than_deletes_a_false_positive(self, tmp_path):
        from guardian.core.models import Finding
        from guardian.llm.verifier import AIFindingVerifier

        (tmp_path / "a.py").write_text("def f():\n    pass\n" * 20)
        reply = json.dumps({"findings": [{
            "evidence_ids": ["x"], "verdict": "false_positive", "confidence": 0.95,
            "reason": "the value is a compile-time constant", "recommendation": "none"}]})
        finding = Finding(category="SQL Injection", severity="High", rule_id="X",
                          file="a.py", line=5, snippet="s", recommendation="r",
                          confidence=0.9)
        out = AIFindingVerifier(
            service=NemotronReasoningService(llm=FakeLLM(reply))
        ).verify_findings(tmp_path, [finding])

        assert len(out) == 1, "triage must never remove a finding"
        assert out[0].confidence <= 0.3
        assert "likely false positive" in out[0].recommendation

    def test_domain_reranking_only_picks_from_deterministic_candidates(self, tmp_path):
        from guardian.intent.classifier import DomainClassifier, DomainVerdict

        (tmp_path / "README.md").write_text("A payments and refunds platform.")
        verdict = DomainVerdict(domain="Banking / FinTech", confidence=0.5,
                                alternatives=[("Retail / E-commerce", 0.2)])
        reply = json.dumps({"primary_domain": "Astrology",  # not a candidate
                            "confidence": 0.99, "reasoning": "made up"})
        out = DomainClassifier()._ai_rerank_pass(
            tmp_path, verdict, service=NemotronReasoningService(llm=FakeLLM(reply)))
        assert out.domain == "Banking / FinTech", "a model cannot invent a domain"

    def test_domain_reranking_accepts_a_valid_candidate(self, tmp_path):
        from guardian.intent.classifier import DomainClassifier, DomainVerdict

        (tmp_path / "README.md").write_text("An online storefront and checkout.")
        verdict = DomainVerdict(domain="Banking / FinTech", confidence=0.4,
                                alternatives=[("Retail / E-commerce", 0.3)])
        reply = json.dumps({"primary_domain": "Retail / E-commerce",
                            "confidence": 0.8, "reasoning": "storefront and checkout"})
        out = DomainClassifier()._ai_rerank_pass(
            tmp_path, verdict, service=NemotronReasoningService(llm=FakeLLM(reply)))
        assert out.domain == "Retail / E-commerce"
        assert "AI re-ranked" in out.reasoning

    def test_domain_reranking_survives_an_llm_failure(self, tmp_path):
        from guardian.intent.classifier import DomainClassifier, DomainVerdict

        (tmp_path / "README.md").write_text("A payments platform.")
        verdict = DomainVerdict(domain="Banking / FinTech", confidence=0.5,
                                alternatives=[("Insurance", 0.2)])
        out = DomainClassifier()._ai_rerank_pass(
            tmp_path, verdict,
            service=NemotronReasoningService(llm=FakeLLM(error=LLMError("503"))))
        assert out.domain == "Banking / FinTech"
