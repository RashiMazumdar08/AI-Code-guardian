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


# ---------------------------------------------------------------------------
# Business Relevance Candidate Context Enrichment Tests
# ---------------------------------------------------------------------------
class TestBusinessCandidateContextEnrichment:
    def test_business_score_ranks_order_cancellation_high(self, tmp_path):
        from guardian.intent.matcher.rule_matcher import RuleMatcher
        fixture_dir = tmp_path / "app"
        fixture_dir.mkdir(parents=True)
        order_file = fixture_dir / "order_service.py"
        order_file.write_text("""
def cancel_order(order_id, reason):
    order = db.orders.find_one({"_id": order_id})
    order["status"] = "CANCELLED"
    db.orders.update({"_id": order_id}, order)
    return order

def calculate_checksum(data):
    return hash(data)
""")
        profiles = RuleMatcher._profiles_from_workspace(fixture_dir)
        cancel_prof = next(p for p in profiles if p.function_name == "cancel_order")
        checksum_prof = next(p for p in profiles if p.function_name == "calculate_checksum")

        assert cancel_prof.business_score > checksum_prof.business_score
        assert cancel_prof.business_score >= 5.0

    def test_business_agent_candidate_enrichment_flow(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "order_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "order.py").write_text("""
def cancel_order(order_id):
    order = db.find(order_id)
    order.status = 'CANCELLED'
    db.save(order)
""")
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("XAI_API_KEY", "test_key")

        # Mock ReasoningGateway inside agent module
        captured_reqs = []
        fake_response_json = json.dumps({
            "summary": "AI Business Analysis identified missing cancellation approval control",
            "findings": [{
                "evidence_ids": ["E1"],
                "category": "business_intent",
                "severity": "High",
                "confidence": 0.9,
                "verdict": "VIOLATION",
                "reason": "cancel_order mutates status to CANCELLED without verifying shipment state.",
                "recommendation": "Check order shipment status prior to cancellation.",
                "file": "order.py",
                "line": 2,
                "function": "cancel_order",
                "policy_id": "REQ-001"
            }]
        })

        class MockGateway:
            def __init__(self, config):
                self.configured = True

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="test-grok")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-bus-test",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["requirements.txt"],
            "findings": [{
                "rule_id": "REQ-001",
                "rule": "Order cancellation must verify shipment status",
                "status": "PARTIAL",
                "score": 0.50,
                "matched_action": "cancel_order",
                "source_file": "order.py"
            }]
        }
        agent = BusinessAgent()
        new_state = agent.run(state)

        assert new_state.get("business_intent_results", {}).get("grok_status") == "COMPLETED"
        assert "ai_business_insights" in new_state
        assert len(new_state["ai_business_insights"]) == 1
        assert new_state["ai_business_insights"][0].get("verdict") == "VIOLATION"
        assert len(captured_reqs) >= 1
        assert any("Source Snippet:" in req.evidence_block and "cancel_order" in req.evidence_block for req in captured_reqs)


    def test_agentic_scan_result_includes_ai_business_insights(self):
        from backend.app.api.v1.agentic_scan import _build_agentic_analysis_result
        record = {"source_scan_id": "base-123", "status": "COMPLETED", "scan_mode": "full_scan"}
        curated = {
            "completed_agents": ["business"],
            "business_violations": [{"rule_id": "REQ-001", "status": "VIOLATION"}],
            "business_intent_results": {"grok_status": "COMPLETED", "agent_reason": "AI verified"},
            "ai_business_insights": [{
                "evidence_ids": ["E1"],
                "category": "business_intent",
                "reason": "Missing shipment status check",
                "file": "order.py",
                "line": 2
            }]
        }

        res = _build_agentic_analysis_result("agentic_test_123", record, curated)
        assert "ai_business_insights" in res
        assert len(res["ai_business_insights"]) == 1
        assert "ai_business_insights" in res["business_analysis"]
        assert len(res["business_analysis"]["ai_business_insights"]) == 1

    def test_order_cancellation_unhandled_returns_ai_violation(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "order_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "order.py").write_text("""
def cancel_order(order_id):
    order = db.find(order_id)
    order.status = 'CANCELLED'
    db.save(order)
""")
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("XAI_API_KEY", "test_key")

        fake_response_json = json.dumps({
            "summary": "AI resolved REQ-001 as VIOLATION",
            "findings": [{
                "evidence_ids": ["E1"],
                "category": "business_intent",
                "severity": "High",
                "confidence": 0.9,
                "verdict": "VIOLATION",
                "reason": "cancel_order mutates status to CANCELLED without verifying if order status is SHIPPED.",
                "recommendation": "Check order shipment status prior to cancellation.",
                "file": "order.py",
                "line": 2,
                "function": "cancel_order",
                "policy_id": "REQ-001"
            }]
        })

        class MockGateway:
            def __init__(self, config):
                self.configured = True

            def reason(self, req):
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="test-grok")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-bus-unhandled",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["requirements.txt"],
            "findings": [{
                "rule_id": "REQ-001",
                "rule": "Customers may cancel an order only before the order is shipped.",
                "status": "INSUFFICIENT_EVIDENCE",
                "score": 0.35,
                "matched_action": "cancel_order",
                "matched_condition": "none",
                "matched_control": "generic_control",
                "what": "Missing shipment status check",
                "source_file": "order.py"
            }]
        }

        agent = BusinessAgent()
        new_state = agent.run(state)

        assert "ai_business_insights" in new_state
        assert len(new_state["ai_business_insights"]) == 1
        insight = new_state["ai_business_insights"][0]
        assert insight.get("verdict") == "VIOLATION"
        assert insight.get("source") == "AI_VALIDATED"
        assert insight.get("rule_id") == "REQ-001"
        assert any(v.get("rule_id") == "REQ-001" for v in new_state.get("business_violations", []))

    def test_order_cancellation_with_check_returns_ai_compliant(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "order_app_compliant"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "order.py").write_text("""
def cancel_order(order_id):
    order = db.find(order_id)
    if order.status == 'SHIPPED':
        raise Exception("Cannot cancel shipped order")
    order.status = 'CANCELLED'
    db.save(order)
""")
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("XAI_API_KEY", "test_key")

        fake_response_json = json.dumps({
            "summary": "AI resolved REQ-001 as COMPLIANT",
            "findings": [{
                "evidence_ids": ["E1"],
                "category": "business_intent",
                "severity": "Info",
                "confidence": 0.95,
                "verdict": "COMPLIANT",
                "reason": "cancel_order verifies order status is not SHIPPED before cancelling.",
                "recommendation": "None",
                "file": "order.py",
                "line": 2,
                "function": "cancel_order",
                "policy_id": "REQ-001"
            }]
        })

        class MockGateway:
            def __init__(self, config):
                self.configured = True

            def reason(self, req):
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="test-grok")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-bus-compliant",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["requirements.txt"],
            "findings": [{
                "rule_id": "REQ-001",
                "rule": "Customers may cancel an order only before the order is shipped.",
                "status": "PARTIAL",
                "score": 0.65,
                "matched_action": "cancel_order",
                "matched_condition": "order.status == 'SHIPPED'",
                "matched_control": "status_check",
                "what": "Partial policy alignment",
                "source_file": "order.py"
            }]
        }

        agent = BusinessAgent()
        new_state = agent.run(state)

        assert "ai_business_insights" in new_state
        assert len(new_state["ai_business_insights"]) == 1
        insight = new_state["ai_business_insights"][0]
        assert insight.get("verdict") == "COMPLIANT"
        assert insight.get("source") == "AI_VALIDATED"
        assert insight.get("rule_id") == "REQ-001"

    def test_dv_bookshop_deterministic_findings_in_prompt(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "dv_bookshop_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "app.py").write_text("""
def profile():
    user = session.get("user")
    return render_template("profile.html", user=user)

def process_order(order_id):
    order = db.get(order_id)
    return order
""")
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("XAI_API_KEY", "test_key")

        captured_reqs = []
        fake_response_json = json.dumps({"summary": "DV-Bookshop resolution", "findings": []})

        class MockGateway:
            def __init__(self, config):
                self.configured = True

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="test-grok")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-dv-bookshop-prompt",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 2,
            "documents": ["policy.md"],
            "findings": [
                {
                    "rule_id": "REQ-008",
                    "rule": "Control 'generic_control' detected but target action requires review",
                    "status": "PARTIAL",
                    "score": 0.28,
                    "matched_action": "profile",
                    "matched_condition": "none",
                    "matched_control": "generic_control",
                    "what": "Partial policy alignment",
                    "source_file": "app.py"
                },
                {
                    "rule_id": "REQ-001",
                    "rule": "Order processing audit log required",
                    "status": "INSUFFICIENT_EVIDENCE",
                    "score": 0.15,
                    "matched_action": "process_order",
                    "matched_condition": "none",
                    "matched_control": "audit_log",
                    "what": "Unverified audit control",
                    "source_file": "app.py"
                }
            ]
        }

        agent = BusinessAgent()
        agent.run(state)

        assert len(captured_reqs) == 2
        req_by_id = {
            ("REQ-008" if "[POLICY REQ-008]" in r.business_block else "REQ-001"): r
            for r in captured_reqs
        }
        req = req_by_id["REQ-008"]

        # Verify REQ-008 in business_block
        assert "[POLICY REQ-008]" in req.business_block
        assert "Requirement: Control 'generic_control' detected but target action requires review" in req.business_block
        assert "Verdict: PARTIAL" in req.business_block
        assert "Score: 0.28" in req.business_block
        assert "Action: profile" in req.business_block

        # Verify REQ-001 in second request business_block
        req2 = req_by_id["REQ-001"]
        assert "[POLICY REQ-001]" in req2.business_block
        assert "Requirement: Order processing audit log required" in req2.business_block
        assert "Verdict: INSUFFICIENT_EVIDENCE" in req2.business_block
        assert "Score: 0.15" in req2.business_block
        assert "Action: process_order" in req2.business_block

        # Verify code snippets / implementation profiles reach evidence_block
        assert "profile" in req.evidence_block or "app.py" in req.evidence_block

    def test_high_confidence_compliant_rules_do_not_call_groq(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "compliant_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "app.py").write_text("def process_payment(): pass\n")

        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test_groq_key")

        captured_reqs = []

        class MockGateway:
            def __init__(self, config):
                self.configured = True
                self.model_name = "groq/llama-3.3-70b"

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-compliant-groq-skip",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["policy.md"],
            "findings": [
                {
                    "rule_id": "REQ-100",
                    "rule": "Payment transactions must be audited",
                    "status": "COMPLIANT",
                    "score": 0.95,
                    "matched_action": "process_payment",
                    "source_file": "app.py"
                }
            ]
        }

        agent = BusinessAgent()
        new_state = agent.run(state)

        # Groq reasoning must NOT be invoked when all rules are high-confidence COMPLIANT
        assert len(captured_reqs) == 0
        assert new_state["business_intent_results"].get("grok_status") == "SKIPPED"

    def test_partial_rules_call_groq(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "partial_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "app.py").write_text("def refund(): pass\n")

        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test_groq_key")

        captured_reqs = []
        fake_response_json = json.dumps({"summary": "Partial rule resolved", "findings": []})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
                self.model_name = "groq/llama-3.3-70b"

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="groq-model")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-partial-groq",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["policy.md"],
            "findings": [
                {
                    "rule_id": "REQ-101",
                    "rule": "Refunds above 50,000 require manager signoff",
                    "status": "PARTIAL",
                    "score": 0.50,
                    "matched_action": "refund",
                    "source_file": "app.py"
                }
            ]
        }

        agent = BusinessAgent()
        new_state = agent.run(state)

        assert len(captured_reqs) == 1
        assert captured_reqs[0].max_tokens == 250
        assert new_state["business_intent_results"].get("grok_status") == "COMPLETED"

    def test_insufficient_evidence_rules_call_groq(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "insufficient_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "app.py").write_text("def withdraw(): pass\n")

        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test_groq_key")

        captured_reqs = []
        fake_response_json = json.dumps({"summary": "Insufficient rule resolved", "findings": []})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
                self.model_name = "groq/llama-3.3-70b"

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="groq-model")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-insufficient-groq",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["policy.md"],
            "findings": [
                {
                    "rule_id": "REQ-102",
                    "rule": "Withdrawals must be rate limited",
                    "status": "INSUFFICIENT_EVIDENCE",
                    "score": 0.20,
                    "matched_action": "withdraw",
                    "source_file": "app.py"
                }
            ]
        }

        agent = BusinessAgent()
        new_state = agent.run(state)

        assert len(captured_reqs) == 1
        assert captured_reqs[0].max_tokens == 250
        assert new_state["business_intent_results"].get("grok_status") == "COMPLETED"

    def test_oversized_workspace_context_is_not_sent(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "large_app"
        fixture_dir.mkdir(parents=True)
        # Create a large source file with 50+ lines
        large_code = "\n".join([f"def func_{i}(): pass" for i in range(50)])
        (fixture_dir / "large.py").write_text(large_code)

        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test_groq_key")

        captured_reqs = []
        fake_response_json = json.dumps({"summary": "Compact context check", "findings": []})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
                self.model_name = "groq/llama-3.3-70b"

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_response_json, model="groq-model")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-large-context",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["policy.md"],
            "findings": [
                {
                    "rule_id": "REQ-200",
                    "rule": "Large function audit check",
                    "status": "PARTIAL",
                    "score": 0.40,
                    "matched_action": "func_0",
                    "source_file": "large.py"
                }
            ]
        }

        agent = BusinessAgent()
        agent.run(state)

        assert len(captured_reqs) == 1
        req = captured_reqs[0]
        # Verify prompt context is truncated and bounded (under 1500 tokens / 6000 chars)
        prompt_len = len(req.business_block) + len(req.evidence_block)
        assert prompt_len < 3000
        assert req.max_tokens == 250

    def test_business_agent_requested_tokens_under_budget(self, tmp_path, monkeypatch):
        """Regression test: verify BusinessAgent single-policy total requested tokens stay below 1,200 tokens."""
        from guardian.agents.business.agent import BusinessAgent
        from guardian.orchestrator.state import create_initial_state

        fixture_dir = tmp_path / "budget_app"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "order.py").write_text("""
def cancel_order(order_id):
    order = db.find(order_id)
    order.status = 'CANCELLED'
    db.save(order)
""")
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("XAI_API_KEY", "test_key")

        captured_reqs = []

        class MockGateway:
            def __init__(self, config):
                self.configured = True
                self.model_name = "groq/llama-3.3-70b"

            def reason(self, req):
                captured_reqs.append(req)
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response('{"summary":"ok","findings":[]}', model="groq-model")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = create_initial_state(
            scan_id="scan-bus-budget-test",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["flask"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": 1,
            "documents": ["requirements.txt"],
            "findings": [{
                "rule_id": "REQ-001",
                "rule": "Customers may cancel an order only before the order is shipped.",
                "status": "PARTIAL",
                "score": 0.50,
                "matched_action": "cancel_order",
                "source_file": "order.py"
            }]
        }

        agent = BusinessAgent()
        agent.run(state)

        assert len(captured_reqs) == 1
        req = captured_reqs[0]

        service = NemotronReasoningService()
        prompt, _ = service._build_prompt(req)
        sys_tokens = len(req.system_role) // 4
        user_tokens = len(prompt) // 4
        input_tokens = sys_tokens + user_tokens
        max_output = req.max_tokens or 350
        total_requested = input_tokens + max_output

        assert total_requested <= 1200, f"Total requested tokens {total_requested} exceeded 1200 limit!"


class TestBusinessAgentMultiBatchStatusAggregation:
    def _create_state_with_findings(self, tmp_path, findings_list):
        from guardian.orchestrator.state import create_initial_state
        fixture_dir = tmp_path / "batch_app"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        (fixture_dir / "app.py").write_text("def action_one(): pass\ndef action_two(): pass\n")
        state = create_initial_state(
            scan_id="scan-batch-test",
            repository_profile={"repo_path": str(fixture_dir), "frameworks": ["python"]}
        )
        state["business_intent_results"] = {
            "status": "SUCCESS",
            "total_rules": len(findings_list),
            "documents": ["policy.md"],
            "findings": findings_list
        }
        return state

    def test_multi_batch_all_successful_results_in_completed(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        fake_res_json = json.dumps({"summary": "ok", "findings": [{
            "evidence_ids": ["E1"], "category": "business_intent", "severity": "High",
            "confidence": 0.9, "verdict": "VIOLATION", "reason": "Missing check",
            "recommendation": "Add check", "file": "app.py", "line": 1
        }]})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                from guardian.reasoning.schemas import parse_business_intent_response
                parsed = parse_business_intent_response(fake_res_json, model="gemini-3.8-flash")
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(response=parsed, available=True)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {"rule_id": "REQ-001", "rule": "Rule 1", "status": "PARTIAL", "score": 0.5, "matched_action": "action_one", "source_file": "app.py"},
            {"rule_id": "REQ-002", "rule": "Rule 2", "status": "PARTIAL", "score": 0.5, "matched_action": "action_two", "source_file": "app.py"},
        ]
        state = self._create_state_with_findings(tmp_path, findings)
        new_state = BusinessAgent().run(state)

        assert new_state["business_intent_results"]["grok_status"] == "COMPLETED"
        assert len(new_state["ai_business_insights"]) == 2

    def test_multi_batch_first_success_second_skipped_budget_results_in_partial(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        call_count = 0
        fake_res_json = json.dumps({"summary": "ok", "findings": [{
            "evidence_ids": ["E1"], "category": "business_intent", "severity": "High",
            "confidence": 0.9, "verdict": "VIOLATION", "reason": "Batch 1 check",
            "recommendation": "Add check", "file": "app.py", "line": 1
        }]})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                nonlocal call_count
                call_count += 1
                from guardian.reasoning.gateway import ReasoningResult
                if call_count == 1:
                    from guardian.reasoning.schemas import parse_business_intent_response
                    parsed = parse_business_intent_response(fake_res_json, model="gemini-3.8-flash")
                    return ReasoningResult(response=parsed, available=True)
                else:
                    return ReasoningResult(available=False, error="SKIPPED_BUDGET: Token budget reserved reached")

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {"rule_id": "REQ-001", "rule": "Rule 1", "status": "PARTIAL", "score": 0.5, "matched_action": "action_one", "source_file": "app.py"},
            {"rule_id": "REQ-002", "rule": "Rule 2", "status": "PARTIAL", "score": 0.5, "matched_action": "action_two", "source_file": "app.py"},
        ]
        state = self._create_state_with_findings(tmp_path, findings)
        new_state = BusinessAgent().run(state)

        assert new_state["business_intent_results"]["grok_status"] == "PARTIAL"
        assert len(new_state["ai_business_insights"]) == 1
        assert "completed successfully for 1 policy batch" in new_state["business_intent_results"]["agent_reason"]
        assert "skipped because the scan token budget was exhausted" in new_state["business_intent_results"]["agent_reason"]

    def test_multi_batch_first_success_second_daily_quota_results_in_partial(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        call_count = 0
        fake_res_json = json.dumps({"summary": "ok", "findings": [{
            "evidence_ids": ["E1"], "category": "business_intent", "severity": "High",
            "confidence": 0.9, "verdict": "VIOLATION", "reason": "Batch 1 check",
            "recommendation": "Add check", "file": "app.py", "line": 1
        }]})

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                nonlocal call_count
                call_count += 1
                from guardian.reasoning.gateway import ReasoningResult
                if call_count == 1:
                    from guardian.reasoning.schemas import parse_business_intent_response
                    parsed = parse_business_intent_response(fake_res_json, model="gemini-3.8-flash")
                    return ReasoningResult(response=parsed, available=True)
                else:
                    return ReasoningResult(available=False, error="PROVIDER_DAILY_QUOTA: 429 ResourceExhausted 200k TPD limit reached")

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {"rule_id": "REQ-001", "rule": "Rule 1", "status": "PARTIAL", "score": 0.5, "matched_action": "action_one", "source_file": "app.py"},
            {"rule_id": "REQ-002", "rule": "Rule 2", "status": "PARTIAL", "score": 0.5, "matched_action": "action_two", "source_file": "app.py"},
        ]
        state = self._create_state_with_findings(tmp_path, findings)
        new_state = BusinessAgent().run(state)

        assert new_state["business_intent_results"]["grok_status"] == "PARTIAL"
        assert len(new_state["ai_business_insights"]) == 1
        assert "completed successfully for 1 policy batch" in new_state["business_intent_results"]["agent_reason"]
        assert "provider daily quota" in new_state["business_intent_results"]["agent_reason"]

    def test_multi_batch_all_skipped_budget(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(available=False, error="SKIPPED_BUDGET: Token budget reached")

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {"rule_id": "REQ-001", "rule": "Rule 1", "status": "PARTIAL", "score": 0.5, "matched_action": "action_one", "source_file": "app.py"},
        ]
        state = self._create_state_with_findings(tmp_path, findings)
        new_state = BusinessAgent().run(state)

        assert new_state["business_intent_results"]["grok_status"] == "SKIPPED_BUDGET"

    def test_multi_batch_all_daily_quota(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                from guardian.reasoning.gateway import ReasoningResult
                return ReasoningResult(available=False, error="PROVIDER_DAILY_QUOTA: 429 ResourceExhausted limit reached")

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {"rule_id": "REQ-001", "rule": "Rule 1", "status": "PARTIAL", "score": 0.5, "matched_action": "action_one", "source_file": "app.py"},
        ]
        state = self._create_state_with_findings(tmp_path, findings)
        new_state = BusinessAgent().run(state)

        assert new_state["business_intent_results"]["grok_status"] == "PROVIDER_DAILY_QUOTA"


class TestPolicyAwareCandidateSelection:
    """Tests proving policy-aware AST candidate selection and ReasoningRequest structure."""

    def test_unrelated_ast_candidate_not_selected(self, tmp_path, monkeypatch):
        from guardian.agents.business.agent import BusinessAgent

        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("LLM_AGENT_BUSINESS_ENABLED", "true")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        captured_requests = []

        class MockGateway:
            def __init__(self, config):
                self.configured = True
            def reason(self, req):
                captured_requests.append(req)
                from guardian.reasoning.gateway import ReasoningResult
                from guardian.reasoning.schemas import ReasoningResponse
                resp = ReasoningResponse(findings=[], summary="Evaluated policy", task="business_intent")
                return ReasoningResult(available=True, response=resp)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        from guardian.intent.matcher.rule_matcher import BehaviorProfile
        dummy_ws_profiles = [
            BehaviorProfile(
                function_name="DependencyAnalysisSection",
                file="frontend/src/components/dependency/DependencyAnalysisSection.tsx",
                line=1,
                actions=["dependency"],
                controls=[],
                code_snippet="export function DependencyAnalysisSection() { return <div>Dependencies</div>; }",
                business_score=10.0
            ),
            BehaviorProfile(
                function_name="process_refund",
                file="services/payment.py",
                line=42,
                actions=["refund"],
                controls=["approval"],
                code_snippet="def process_refund(amount): if amount > 50000 and not has_approval(): raise Error()",
                business_score=5.0
            )
        ]
        monkeypatch.setattr("guardian.intent.matcher.rule_matcher.RuleMatcher._profiles_from_workspace", lambda repo_path=None: dummy_ws_profiles)

        findings = [
            {
                "rule_id": "REQ-008",
                "original_requirement": "Control 'generic_control' detected but target action requires review",
                "rule": "Control 'generic_control' detected but target action requires review",
                "status": "PARTIAL",
                "score": 0.28,
                "matched_action": "refund",
                "matched_condition": "none",
                "matched_control": "approval",
                "missing_control": "manager approval",
                "evidence": "file: services/payment.py · function: process_refund",
                "matched_file": "services/payment.py",
                "matched_function": "process_refund",
                "matched_snippet": "def process_refund(amount): if amount > 50000 and not has_approval(): raise Error()"
            }
        ]

        state = {
            "scan_id": "test_policy_aware_001",
            "repository_profile": {"repo_path": str(tmp_path)},
            "business_intent_results": {"status": "SUCCESS", "findings": findings},
            "business_context": {"domain": "e-commerce", "criticality": "HIGH"}
        }

        BusinessAgent()._process(state)

        assert len(captured_requests) == 1
        req = captured_requests[0]

        # 1. Original requirement text included
        assert "Control 'generic_control' detected but target action requires review" in req.business_block

        # 2. Deterministic verdict/score/evidence included
        assert "Deterministic Verdict:\nPARTIAL" in req.business_block
        assert "Deterministic Score:\n0.28" in req.business_block
        assert "Matched Action:\nrefund" in req.business_block
        assert "Matched Control:\napproval" in req.business_block

        # 3. Policy-specific AST candidate selected (payment.py), unrelated file excluded (DependencyAnalysisSection.tsx)
        assert "services/payment.py" in req.evidence_block
        assert "process_refund" in req.evidence_block
        assert "DependencyAnalysisSection.tsx" not in req.evidence_block


class TestCanonicalDocumentParsing:
    def test_dv_bookshop_canonical_parsing(self, monkeypatch, tmp_path):
        from pathlib import Path
        from guardian.intent.ingestion.document_loader import DocumentLoader
        from guardian.intent.parser.rule_parser import RuleParser
        from guardian.intent.matcher.rule_matcher import RuleMatcher
        from guardian.agents.business.agent import BusinessAgent

        pdf_path = Path("data/business_docs/DV_Bookshop_Business_Rules.pdf")
        if not pdf_path.exists():
            pytest.skip("DV_Bookshop_Business_Rules.pdf not found in data/business_docs")

        loader = DocumentLoader(docs_dir=pdf_path.parent)
        requirements = loader.extract_actionable_requirements()

        # 1. Exactly 5 rules parsed for DV-Bookshop document
        assert len(requirements) == 5

        # 2. IDs equal ['REQ-001', 'REQ-002', 'REQ-003', 'REQ-004', 'REQ-005']
        req_ids = [r.id for r in requirements]
        assert req_ids == ["REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"]

        # 3. No duplicate IDs
        assert len(set(req_ids)) == 5

        # 4. Purpose text is not a rule
        for r in requirements:
            assert "This document defines the canonical business logic" not in r.text
            assert "Purpose" not in r.id

        # 5. Summary table does not create separate rule objects (area & required_control enriched)
        req_001 = next(r for r in requirements if r.id == "REQ-001")
        assert req_001.area == "Cart / inventory"
        assert req_001.required_control == "Positive quantity and available stock"

        # 6. "Recommended AI Code Guardian Test" is not a rule
        for r in requirements:
            assert "Recommended AI Code Guardian Test" not in r.id
            assert "Verify that attempting to add quantity <= 0" not in r.id

        # 7. Each rule contains its correct original Business Requirement text
        assert "positive, valid quantity" in req_001.text

        # 8. REQ-001 does not contain REQ-002 / REQ-003 text
        assert "double-spend" not in req_001.text
        assert "Checkout pricing" not in req_001.text

        # 9. REQ-002 requirement body does not contain summary table rows
        req_002 = next(r for r in requirements if r.id == "REQ-002")
        assert "Balance transfer" not in req_002.text

        # 10. BusinessAgent receives only canonical rule objects
        parser = RuleParser()
        parsed_rules = parser.parse_all(requirements)
        matcher = RuleMatcher()
        eval_results = matcher.evaluate_all(parsed_rules, findings=[])

        captured_requests = []
        class MockGateway:
            configured = True
            def __init__(self, config=None):
                self.configured = True
            def reason(self, req):
                captured_requests.append(req)
                from guardian.reasoning.gateway import ReasoningResult
                from guardian.reasoning.schemas import ReasoningResponse
                return ReasoningResult(available=True, response=ReasoningResponse(findings=[], summary="OK", task="business_intent"))
            def request_reasoning(self, req):
                return self.reason(req)

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        state = {
            "scan_id": "test_canonical_001",
            "repository_profile": {"repo_path": str(tmp_path)},
            "business_intent_results": {"status": "SUCCESS", "findings": eval_results},
            "business_context": {"domain": "e-commerce", "criticality": "HIGH"}
        }

        BusinessAgent()._process(state)
        assert len(captured_requests) > 0
        all_req_b_text = "\n".join(r.business_block for r in captured_requests)
        for expected_id in ["REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"]:
            assert f"[POLICY {expected_id}]" in all_req_b_text


class TestBusinessAgentAdmissionAndEvidenceSearch:
    def test_admission_eligibility_and_candidate_search(self, monkeypatch, tmp_path):
        from guardian.agents.business.agent import BusinessAgent
        from guardian.intent.matcher.rule_matcher import BehaviorProfile

        dummy_ws_profiles = [
            BehaviorProfile(
                function_name="DependencyAnalysisSection",
                file="frontend/src/components/dependency/DependencyAnalysisSection.tsx",
                line=1,
                actions=["dependency"],
                controls=[],
                code_snippet="export function DependencyAnalysisSection() { return <div>Dependencies</div>; }",
                business_score=10.0
            ),
            BehaviorProfile(
                function_name="transfer_balance",
                file="services/account_service.py",
                line=100,
                actions=["transfer"],
                controls=["atomic", "balance_check"],
                code_snippet="def transfer_balance(sender_id, recipient_id, amount):\n  with db.transaction():\n    check_balance(sender_id, amount)\n    update_balance(sender_id, -amount)",
                business_score=8.0
            ),
            BehaviorProfile(
                function_name="calculate_order_total",
                file="services/checkout_service.py",
                line=50,
                actions=["checkout"],
                controls=["authoritative_pricing"],
                code_snippet="def calculate_order_total(cart_id):\n  total = sum(item.book.price * item.quantity for item in get_cart(cart_id))\n  return total",
                business_score=8.0
            )
        ]
        monkeypatch.setattr("guardian.intent.matcher.rule_matcher.RuleMatcher._profiles_from_workspace", lambda repo_path=None: dummy_ws_profiles)

        captured_requests = []
        class MockGateway:
            configured = True
            def __init__(self, config=None):
                self.configured = True
            def reason(self, req):
                captured_requests.append(req)
                from guardian.reasoning.gateway import ReasoningResult
                from guardian.reasoning.schemas import ReasoningResponse, ReasoningFinding
                f_id = req.business_block.split("[POLICY ")[1].split("]")[0] if "[POLICY " in req.business_block else "REQ-001"
                finding = ReasoningFinding(
                    title=f"AI Evaluated {f_id}",
                    category="business",
                    severity="Medium",
                    confidence=0.9,
                    reason=f"Semantically resolved policy {f_id}",
                    recommendation="Maintain implementation",
                    extras={"verdict": "COMPLIANT", "policy_id": f_id}
                )
                return ReasoningResult(available=True, response=ReasoningResponse(findings=[finding], summary="OK", task="business_intent"))

        monkeypatch.setattr("guardian.reasoning.gateway.ReasoningGateway", MockGateway)

        findings = [
            {
                "rule_id": "REQ-001",
                "original_requirement": "Cart quantity positive check required",
                "status": "PARTIAL",
                "score": 0.4,
                "matched_action": "cart",
                "matched_control": "quantity",
                "matched_file": "services/cart.py",
                "matched_function": "add_item",
                "matched_line": 10,
                "matched_snippet": "def add_item(qty):\n  if qty <= 0:\n    raise Error()"
            },
            {
                "rule_id": "REQ-002",
                "original_requirement": "A balance transfer must be atomic. The sender must have sufficient funds, and concurrent requests must not double spend.",
                "title": "Balance Transfer Integrity Rule",
                "area": "Balance transfer",
                "required_control": "Atomic check/update; no double-spend",
                "status": "INSUFFICIENT_EVIDENCE",
                "score": 0.0,
                "matched_action": "generic_action",
                "matched_control": "generic_control",
                "matched_file": "",
                "matched_function": "",
                "matched_snippet": ""
            },
            {
                "rule_id": "REQ-003",
                "original_requirement": "The final amount charged for an order must be calculated by the server from authoritative book prices, quantities, and discounts.",
                "title": "Authoritative Checkout Price Rule",
                "area": "Checkout pricing",
                "required_control": "Server-calculated total is authoritative",
                "status": "INSUFFICIENT_EVIDENCE",
                "score": 0.0,
                "matched_action": "generic_action",
                "matched_control": "generic_control",
                "matched_file": "",
                "matched_function": "",
                "matched_snippet": ""
            }
        ]

        state = {
            "scan_id": "test_admission_001",
            "repository_profile": {"repo_path": str(tmp_path)},
            "business_intent_results": {"status": "SUCCESS", "findings": findings},
            "business_context": {"domain": "e-commerce", "criticality": "HIGH"}
        }

        res_state = BusinessAgent()._process(state)

        # Assert all 3 inconclusive/zero-score findings were sent to Gateway
        assert len(captured_requests) == 3

        req_by_id = {}
        for r in captured_requests:
            if "[POLICY REQ-001]" in r.business_block:
                req_by_id["REQ-001"] = r
            elif "[POLICY REQ-002]" in r.business_block:
                req_by_id["REQ-002"] = r
            elif "[POLICY REQ-003]" in r.business_block:
                req_by_id["REQ-003"] = r

        req1 = req_by_id["REQ-001"]
        req2 = req_by_id["REQ-002"]
        req3 = req_by_id["REQ-003"]

        # REQ-002 candidate evidence checks
        assert "services/account_service.py" in req2.evidence_block
        assert "transfer_balance" in req2.evidence_block
        assert "DependencyAnalysisSection.tsx" not in req2.evidence_block

        # REQ-003 candidate evidence checks
        assert "services/checkout_service.py" in req3.evidence_block
        assert "calculate_order_total" in req3.evidence_block
        assert "DependencyAnalysisSection.tsx" not in req3.evidence_block

        # Assert state tracking
        bi_res = res_state.get("business_intent_results", {})
        assert "REQ-001" in bi_res.get("analyzed_policies", [])
        assert "REQ-002" in bi_res.get("analyzed_policies", [])
        assert "REQ-003" in bi_res.get("analyzed_policies", [])
        assert len(res_state.get("ai_business_insights", [])) == 3


class TestBusinessAgentConceptAndPriority:
    def test_req002_rejects_ai_infrastructure_files(self):
        from guardian.agents.business.agent import _rank_workspace_candidates
        from guardian.intent.matcher.rule_matcher import BehaviorProfile

        req_f = {
            "rule_id": "REQ-002",
            "original_requirement": "Transfer operations between accounts must maintain balance integrity. Sender balance must decrease by amount and receiver balance increase by amount atomically.",
            "title": "Balance Transfer Integrity Rule",
            "area": "Balance transfer",
            "required_control": "Atomic balance check and update",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
        }

        profiles = [
            BehaviorProfile(
                function_name="check_token_balance",
                file="guardian/ai/local_embedder.py",
                line=129,
                actions=[],
                controls=[],
                code_snippet="def check_token_balance(): # Check remaining embeddings token balance\n pass",
                business_score=8.0,
            ),
            BehaviorProfile(
                function_name="balance_response_length",
                file="guardian/ai/chatbot.py",
                line=72,
                actions=[],
                controls=[],
                code_snippet="def balance_response_length(): # Balance prompt context window\n pass",
                business_score=7.0,
            ),
        ]

        candidates = _rank_workspace_candidates(req_f, profiles)
        assert len(candidates) == 0, "REQ-002 should reject AI infrastructure files (local_embedder.py, chatbot.py)"

    def test_req003_rejects_unrelated_frontend_files(self):
        from guardian.agents.business.agent import _rank_workspace_candidates
        from guardian.intent.matcher.rule_matcher import BehaviorProfile

        req_f = {
            "rule_id": "REQ-003",
            "original_requirement": "The final amount charged for an order must be calculated by the server from authoritative book prices, quantities, and discounts.",
            "title": "Authoritative Checkout Price Rule",
            "area": "Checkout pricing",
            "required_control": "Server-calculated total is authoritative",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
        }

        profiles = [
            BehaviorProfile(
                function_name="DependencyAnalysisSection",
                file="frontend/src/components/dependency/DependencyAnalysisSection.tsx",
                line=48,
                actions=[],
                controls=[],
                code_snippet="export function DependencyAnalysisSection({ price, items }) { return <div>Price</div>; }",
                business_score=9.0,
            ),
            BehaviorProfile(
                function_name="get_price_embedding",
                file="guardian/ai/local_embedder.py",
                line=50,
                actions=[],
                controls=[],
                code_snippet="def get_price_embedding(price): return embedder.encode(price)",
                business_score=8.0,
            ),
        ]

        candidates = _rank_workspace_candidates(req_f, profiles)
        assert len(candidates) == 0, "REQ-003 should reject unrelated frontend and AI infrastructure files"

    def test_insufficient_evidence_highest_ai_priority(self):
        from guardian.agents.business.agent import _policy_priority_key

        f_insufficient = {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE", "score": 0.0}
        f_partial = {"rule_id": "REQ-001", "status": "PARTIAL", "score": 0.5}
        f_violation = {"rule_id": "REQ-004", "status": "VIOLATION", "score": 1.0}
        f_compliant = {"rule_id": "REQ-005", "status": "COMPLIANT", "score": 1.0}

        assert _policy_priority_key(f_insufficient)[0] == 1
        assert _policy_priority_key(f_partial)[0] == 2
        assert _policy_priority_key(f_violation)[0] == 4
        assert _policy_priority_key(f_compliant)[0] == 4

        findings = [f_violation, f_partial, f_insufficient, f_compliant]
        sorted_findings = sorted(findings, key=_policy_priority_key)
        assert [f["rule_id"] for f in sorted_findings] == ["REQ-002", "REQ-001", "REQ-004", "REQ-005"]

    def test_deterministic_violations_do_not_consume_budget_ahead_of_unresolved_policies(self):
        from guardian.agents.business.agent import _policy_priority_key

        findings = [
            {"rule_id": "REQ-004", "status": "VIOLATION", "score": 1.0},
            {"rule_id": "REQ-005", "status": "VIOLATION", "score": 1.0},
            {"rule_id": "REQ-001", "status": "PARTIAL", "score": 0.5},
            {"rule_id": "REQ-002", "status": "INSUFFICIENT_EVIDENCE", "score": 0.0},
            {"rule_id": "REQ-003", "status": "INSUFFICIENT_EVIDENCE", "score": 0.0},
        ]

        sorted_findings = sorted(findings, key=_policy_priority_key)
        ordered_ids = [f["rule_id"] for f in sorted_findings]
        assert ordered_ids.index("REQ-002") < ordered_ids.index("REQ-004")
        assert ordered_ids.index("REQ-003") < ordered_ids.index("REQ-004")
        assert ordered_ids.index("REQ-001") < ordered_ids.index("REQ-004")

    def test_req003_rejects_unrelated_reports_file(self):
        from guardian.agents.business.agent import _rank_workspace_candidates
        from guardian.intent.matcher.rule_matcher import BehaviorProfile

        req_f = {
            "rule_id": "REQ-003",
            "original_requirement": "The final amount charged for an order must be calculated from authoritative book prices, quantities, and applicable discounts. A client-supplied total must never determine the amount charged.",
            "title": "Authoritative Checkout Price Rule",
            "area": "Checkout pricing",
            "required_control": "Server-calculated total is authoritative",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
            "matched_action": "generic_action",
            "matched_control": "generic_control",
        }

        profiles = [
            BehaviorProfile(
                function_name="download_report",
                file="backend/app/api/v1/reports.py",
                line=139,
                actions=[],
                controls=[],
                code_snippet="def download_report(): # Download scan report fallback for bookmarked links\n return report",
                business_score=8.0,
            ),
        ]

        candidates = _rank_workspace_candidates(req_f, profiles)
        assert len(candidates) == 0, "REQ-003 must reject unrelated reports.py download_report evidence"

    def test_generic_words_alone_do_not_qualify(self):
        from guardian.agents.business.agent import _rank_workspace_candidates
        from guardian.intent.matcher.rule_matcher import BehaviorProfile

        req_f = {
            "rule_id": "REQ-003",
            "original_requirement": "Authoritative checkout price rule for order total calculation.",
            "title": "Authoritative Checkout Price Rule",
            "area": "Checkout pricing",
            "status": "INSUFFICIENT_EVIDENCE",
            "score": 0.0,
            "matched_action": "generic_action",
            "matched_control": "generic_control",
        }

        profiles = [
            BehaviorProfile(
                function_name="get_report_data",
                file="backend/app/api/v1/reports.py",
                line=10,
                actions=[],
                controls=[],
                code_snippet="def get_report_data(): # Calculate total amount for PDF report data\n pass",
                business_score=5.0,
            )
        ]

        candidates = _rank_workspace_candidates(req_f, profiles)
        assert len(candidates) == 0, "Generic words in report context must not qualify alone for checkout pricing rule"

    def test_business_intent_engine_defaults_to_deterministic_without_duplicate_llm_calls(self):
        from guardian.intent.engine import BusinessIntentEngine
        engine = BusinessIntentEngine()
        assert engine.use_llm is False, "BusinessIntentEngine must default use_llm=False to preserve BusinessAgent token budget"









