"""
Dynamic Business Intent tests.

The behaviour that matters: the verdict must differ between a repository
that implements a control and one that does not. The previous
keyword-overlap engine could not tell those apart, which is the whole
reason this was rewritten.
"""
from __future__ import annotations

import json

import pytest

from guardian.config import GuardianConfig
from guardian.core.context import AnalysisContext, RepositoryContext
from guardian.engines.base import run_engine
from guardian.engines.business_intent import BusinessIntentEngine
from guardian.engines.security import SecurityEngine
from guardian.evidence.models import EvidenceType
from guardian.policy import ControlType, PolicyExtractor
from guardian.reasoning.gateway import NemotronReasoningService
from guardian.reasoning.schemas import ComplianceVerdict
from guardian.ust import USTBuilder

from test_reasoning import FakeLLM


REQUIREMENTS = (
    "Refunds above INR 50,000 require manager approval.\n"
    "All payment transactions must be logged for audit purposes.\n"
)

REFUND_WITHOUT_APPROVAL = """
public class RefundService {
  public void processRefund(String customerId, long amount) {
    Refund r = new Refund(customerId, amount);
    refundRepository.save(r);
    paymentGateway.refund(r);
  }
}
"""

REFUND_WITH_APPROVAL = """
public class RefundService {
  public void processRefund(String customerId, long amount) {
    if (amount > 50000 && !approvalService.hasManagerApproval(customerId)) {
      throw new UnauthorizedException();
    }
    Refund r = new Refund(customerId, amount);
    refundRepository.save(r);
  }
}
"""

PAYMENT_WITH_AUDIT = """
def process_payment(amount, user):
    if not current_user.has_permission("pay"):
        raise Forbidden()
    auditLog.record("payment", amount)
    db.save(amount)
"""


def build_context(tmp_path, code: dict[str, str], requirements: str = REQUIREMENTS):
    tmp_path.mkdir(parents=True, exist_ok=True)
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(requirements)
    paths = []
    for name, content in code.items():
        p = tmp_path / name
        p.write_text(content)
        paths.append(p)
    repo = RepositoryContext(root=tmp_path, source_files=paths)
    ctx = AnalysisContext(repository=repo, config=GuardianConfig(),
                          business_requirements=[reqs])
    ctx.ust = USTBuilder().build_repository(tmp_path, paths)
    run_engine(SecurityEngine(), ctx)     # publishes structural evidence
    return ctx


def verdict_for(result, action: str) -> str:
    for item in result.output["verdicts"]:
        if action in item["policy"].lower():
            return item["verdict"]
    return "MISSING"


# ---------------------------------------------------------------------------
# Policy extraction
# ---------------------------------------------------------------------------
class TestPolicyExtraction:
    def test_threshold_rule_becomes_structured_policy(self):
        policies = PolicyExtractor().extract_from_text(
            "Refunds above INR 50,000 require manager approval.")
        assert len(policies) == 1
        policy = policies.policies[0]
        assert policy.action == "refund"
        assert policy.required_control is ControlType.AUTHORIZATION
        assert policy.condition.field == "amount"
        assert policy.condition.operator == ">"
        assert policy.condition.value == 50000
        assert policy.condition.unit == "INR"
        assert policy.is_checkable

    @pytest.mark.parametrize("text,expected", [
        ("Refunds above 10 lakh require approval.", 1_000_000),
        ("Transfers exceeding $10,000 require authorization.", 10_000),
        ("Payouts over 2 crore must be approved by a manager.", 20_000_000),
        ("Withdrawals above 5 million require sign-off.", 5_000_000),
    ])
    def test_magnitude_words_are_normalised(self, text, expected):
        policy = PolicyExtractor().extract_from_text(text).policies[0]
        assert policy.condition.value == expected

    @pytest.mark.parametrize("text,control", [
        ("All payments must be logged for audit purposes.", ControlType.AUDIT),
        ("Card numbers must be encrypted at rest.", ControlType.ENCRYPTION),
        ("Login attempts shall be rate limited to 5 per minute.", ControlType.RATE_LIMIT),
        ("Transfers above $10,000 require two-person authorization.",
         ControlType.SEGREGATION),
        ("Refunds require manager approval.", ControlType.AUTHORIZATION),
    ])
    def test_control_type_classification(self, text, control):
        policy = PolicyExtractor().extract_from_text(text).policies[0]
        assert policy.required_control is control

    def test_records_noun_is_not_an_audit_requirement(self):
        """'records belonging to other customers' is access control."""
        policy = PolicyExtractor().extract_from_text(
            "Users must not access account records belonging to other "
            "customers.").policies[0]
        assert policy.required_control is ControlType.AUTHORIZATION
        assert policy.negative

    def test_descriptive_prose_yields_no_policy(self):
        policies = PolicyExtractor().extract_from_text(
            "The system displays a dashboard with charts and graphs.")
        assert len(policies) == 0

    def test_policy_traces_back_to_its_sentence(self):
        text = "Refunds above INR 50,000 require manager approval."
        policy = PolicyExtractor().extract_from_text(text, "brd.md").policies[0]
        assert policy.source_text == text
        assert policy.source_document == "brd.md"

    def test_policy_ids_are_stable(self):
        a = PolicyExtractor().extract_from_text(REQUIREMENTS).policies
        b = PolicyExtractor().extract_from_text(REQUIREMENTS).policies
        assert [p.policy_id for p in a] == [p.policy_id for p in b]

    def test_loads_from_file(self, tmp_path):
        path = tmp_path / "reqs.txt"
        path.write_text(REQUIREMENTS)
        policies = PolicyExtractor().extract_from_sources([path])
        assert len(policies) >= 2
        assert "reqs.txt" in policies.documents


# ---------------------------------------------------------------------------
# Behavioural comparison — the core capability
# ---------------------------------------------------------------------------
class TestBehaviourComparison:
    def test_missing_control_is_a_violation(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert verdict_for(result, "refund") == ComplianceVerdict.VIOLATION.value
        assert any(f.category == "Business Intent Violation" for f in result.findings)

    def test_implemented_control_is_compliant(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITH_APPROVAL})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert verdict_for(result, "refund") == ComplianceVerdict.COMPLIANT.value
        assert not [f for f in result.findings
                    if f.category == "Business Intent Violation"]

    def test_the_two_repositories_differ(self, tmp_path):
        """The regression the old engine could not catch."""
        without = build_context(tmp_path / "a", {"R.java": REFUND_WITHOUT_APPROVAL})
        with_control = build_context(tmp_path / "b", {"R.java": REFUND_WITH_APPROVAL})
        engine = BusinessIntentEngine(use_llm=False)
        a = run_engine(engine, without).output["alignment_score"]
        b = run_engine(engine, with_control).output["alignment_score"]
        assert b > a

    def test_audit_control_detected_across_languages(self, tmp_path):
        ctx = build_context(tmp_path, {"payment.py": PAYMENT_WITH_AUDIT})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert verdict_for(result, "payment") == ComplianceVerdict.COMPLIANT.value

    def test_unimplemented_policy_is_insufficient_evidence_not_violation(self, tmp_path):
        """'We could not find it' must never be reported as 'it is broken'."""
        ctx = build_context(tmp_path, {"unrelated.py": "def render_chart():\n    pass\n"})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert all(v["verdict"] == ComplianceVerdict.INSUFFICIENT_EVIDENCE.value
                   for v in result.output["verdicts"])
        assert result.findings == []

    def test_alignment_score_excludes_unlocated_policies(self, tmp_path):
        ctx = build_context(tmp_path, {"unrelated.py": "def render_chart():\n    pass\n"})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert result.output["alignment_score"] == 100.0

    def test_no_requirements_is_reported_not_guessed(self, tmp_path):
        paths = [tmp_path / "a.py"]
        paths[0].write_text("def f():\n    pass\n")
        ctx = AnalysisContext(repository=RepositoryContext(root=tmp_path,
                                                            source_files=paths),
                              config=GuardianConfig())
        ctx.ust = USTBuilder().build_repository(tmp_path, paths)
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert result.output["status"] == "no_requirements"
        assert result.findings == []


class TestBehaviourEvidence:
    def test_behaviour_evidence_is_published(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        run_engine(BusinessIntentEngine(use_llm=False), ctx)
        behaviour = ctx.evidence.by_type(EvidenceType.BEHAVIOR)
        assert behaviour
        described = behaviour[0].description
        assert "processRefund" in described
        assert "authorization checks: NONE FOUND" in described

    def test_missing_control_evidence_precedes_the_finding(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        result = run_engine(BusinessIntentEngine(use_llm=False), ctx)
        assert ctx.evidence.by_type(EvidenceType.MISSING_CONTROL)
        finding = next(f for f in result.findings
                       if f.category == "Business Intent Violation")
        assert finding.evidence_ids
        for eid in finding.evidence_ids:
            assert ctx.evidence.exists(eid)

    def test_policy_evidence_records_the_written_requirement(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        run_engine(BusinessIntentEngine(use_llm=False), ctx)
        policy_evidence = ctx.evidence.by_type(EvidenceType.BUSINESS_POLICY)
        assert any("50,000" in e.description for e in policy_evidence)

    def test_threshold_absence_is_evidenced(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        run_engine(BusinessIntentEngine(use_llm=False), ctx)
        missing = ctx.evidence.by_type(EvidenceType.MISSING_CONTROL)
        assert any("threshold" in e.operation for e in missing)

    def test_threshold_present_is_not_flagged(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITH_APPROVAL})
        run_engine(BusinessIntentEngine(use_llm=False), ctx)
        missing = ctx.evidence.by_type(EvidenceType.MISSING_CONTROL)
        assert not any("threshold" in e.operation for e in missing)


# ---------------------------------------------------------------------------
# Contextual pass
# ---------------------------------------------------------------------------
class TestContextualPass:
    def _service(self, reply: str) -> NemotronReasoningService:
        return NemotronReasoningService(llm=FakeLLM(reply))

    def test_runs_without_api_key(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        service = NemotronReasoningService(llm=None)
        service._config.api_key = ""
        result = run_engine(
            BusinessIntentEngine(reasoning_service=service, use_llm=True), ctx)
        assert result.output["ai"]["status"] == "unavailable"
        # deterministic verdict is unaffected
        assert verdict_for(result, "refund") == ComplianceVerdict.VIOLATION.value

    def test_llm_failure_preserves_deterministic_results(self, tmp_path):
        from guardian.llm.base import LLMError
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        service = NemotronReasoningService(llm=FakeLLM(error=LLMError("503")))
        result = run_engine(
            BusinessIntentEngine(reasoning_service=service, use_llm=True), ctx)
        assert verdict_for(result, "refund") == ComplianceVerdict.VIOLATION.value
        assert result.ok

    def test_grounded_ai_verdict_becomes_an_ai_validated_finding(self, tmp_path):
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        run_engine(BusinessIntentEngine(use_llm=False), ctx)   # publish evidence
        missing = ctx.evidence.by_type(EvidenceType.MISSING_CONTROL)
        assert missing

        reply = json.dumps({"summary": "s", "findings": [{
            "evidence_ids": [missing[0].id],
            "category": "business_intent", "severity": "High", "confidence": 0.9,
            "verdict": "VIOLATION",
            "reason": "processRefund performs the refund with no approval control.",
            "recommendation": "Require manager approval above the threshold.",
            "file": "RefundService.java", "line": missing[0].line,
            "function": "processRefund"}]})

        fresh = build_context(tmp_path / "again",
                              {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        result = run_engine(BusinessIntentEngine(
            reasoning_service=self._service(reply), use_llm=True), fresh)
        ai_findings = [f for f in result.findings if f.source.startswith("AI")]
        assert ai_findings, "a grounded AI verdict should surface as a finding"
        assert ai_findings[0].source in ("AI_VALIDATED", "AI_SUGGESTED")

    def test_ungrounded_ai_verdict_is_rejected(self, tmp_path):
        reply = json.dumps({"summary": "s", "findings": [{
            "evidence_ids": ["E9999"], "category": "business_intent",
            "severity": "Critical", "confidence": 0.99, "verdict": "VIOLATION",
            "reason": "There is a serious authorization flaw here.",
            "recommendation": "Fix it.", "file": "Imaginary.java", "line": 42,
            "function": "nonExistent"}]})
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        result = run_engine(BusinessIntentEngine(
            reasoning_service=self._service(reply), use_llm=True), ctx)
        assert not [f for f in result.findings if f.source.startswith("AI")]
        reports = result.output["ai"]["reports"]
        assert any(r.get("validation", {}).get("rejected") for r in reports)

    def test_compliant_policies_do_not_trigger_a_model_call(self, tmp_path):
        llm = FakeLLM(json.dumps({"findings": []}))
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITH_APPROVAL,
                                       "payment.py": PAYMENT_WITH_AUDIT})
        run_engine(BusinessIntentEngine(
            reasoning_service=NemotronReasoningService(llm=llm), use_llm=True), ctx)
        assert llm.calls == 0, "clean verdicts must not cost tokens"

    def test_prompt_contains_evidence_not_the_repository(self, tmp_path):
        llm = FakeLLM(json.dumps({"findings": []}))
        ctx = build_context(tmp_path, {"RefundService.java": REFUND_WITHOUT_APPROVAL})
        run_engine(BusinessIntentEngine(
            reasoning_service=NemotronReasoningService(llm=llm), use_llm=True), ctx)
        assert llm.calls >= 1
        prompt = llm.prompts[0]
        assert "EVIDENCE" in prompt
        assert "processRefund" in prompt
        assert len(prompt) < 12_500
