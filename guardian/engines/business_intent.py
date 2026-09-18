"""
Dynamic Business Intent Engine
==============================
Compares what the requirements say with what the code actually does.

    requirements -> structured policies -> UST behavioural evidence
                 -> RAG -> Nemotron comparison -> validation -> finding

The old engine scored keyword overlap between requirement text and file
paths, so it returned the same verdict whether or not the control existed.
This one locates the implementing function in the UST and reads its
behaviour: which calls it makes, whether an authorization check sits on
the path to the state change, whether the threshold in the requirement
appears in a conditional, whether an audit write happens.

That behaviour is published as Evidence *before* any model is consulted,
which is what makes the AI step checkable:

    Function: processRefund
    Parameters: amount, requestBody
    Calls: refundService.refund(), db.save()
    Authorization checks on this path: none          <- E42
    Threshold comparison on 'amount': none           <- E43

Nemotron then judges policy-versus-behaviour and must cite E42/E43. A
verdict citing nothing, or citing evidence that was never supplied, is
rejected by `guardian.reasoning.validation` and never becomes a finding.

Without an API key the engine still runs: deterministic control-presence
analysis produces findings for the unambiguous cases (a policy demands an
authorization control; the implementing function contains no
authorization check anywhere on its path) and reports the rest as
requiring review.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from guardian.core.context import AnalysisContext
from guardian.core.models import Finding, Severity
from guardian.engines.base import BaseEngine, EngineResult
from guardian.evidence.models import Evidence, EvidenceType, FindingSource
from guardian.policy.extractor import PolicyExtractor
from guardian.policy.models import BusinessPolicy, ControlType, PolicySet
from guardian.reasoning.context import render_evidence, render_ust_context
from guardian.reasoning.gateway import ReasoningRequest
from guardian.reasoning.schemas import (
    BUSINESS_INTENT_SCHEMA_INSTRUCTION, ComplianceVerdict,
)
from guardian.reasoning.validation import AIFindingValidator, to_findings
from guardian.ust.models import USTFile, USTNode, USTNodeType

log = logging.getLogger(__name__)

ENGINE_NAME = "business_intent"
DETECTOR = "ust_behavior_analyzer"

MAX_IMPLEMENTATIONS_PER_POLICY = 5

#: Calls that persist state — the point a control must precede.
STATE_CHANGE = re.compile(
    r"(?i)(^|\.)(save|insert|update|delete|persist|create|commit|execute|"
    r"executeUpdate|write|put|post|send|transfer|charge|capture|refund|"
    r"disburse|payout|approve|publish|emit|enqueue)(\.|$)")

#: Calls that write a durable audit record.
AUDIT_WRITE = re.compile(
    r"(?i)(audit|auditlog|audit_log|auditTrail|audit_trail|journal|"
    r"eventlog|event_log|track|record_event|history)")


@dataclass
class BehaviorProfile:
    """What one implementing function actually does."""

    function: str
    file: str
    language: str
    line: int
    end_line: int = 0
    parameters: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    authorization_checks: list[str] = field(default_factory=list)
    state_changes: list[str] = field(default_factory=list)
    audit_writes: list[str] = field(default_factory=list)
    conditionals: int = 0
    threshold_comparisons: list[str] = field(default_factory=list)
    crypto_operations: list[str] = field(default_factory=list)
    rate_limit_markers: list[str] = field(default_factory=list)
    validation_calls: list[str] = field(default_factory=list)

    def has_control(self, control: ControlType) -> bool:
        if control is ControlType.AUTHORIZATION:
            return bool(self.authorization_checks)
        if control is ControlType.SEGREGATION:
            return len(self.authorization_checks) >= 2
        if control is ControlType.AUDIT:
            return bool(self.audit_writes)
        if control is ControlType.ENCRYPTION:
            return bool(self.crypto_operations)
        if control is ControlType.RATE_LIMIT:
            return bool(self.rate_limit_markers)
        if control is ControlType.VALIDATION:
            return bool(self.validation_calls) or self.conditionals > 0
        if control is ControlType.WORKFLOW:
            return self.conditionals > 0
        return False

    def describe(self) -> str:
        lines = [
            f"function {self.function}({', '.join(self.parameters)}) "
            f"at {self.file}:{self.line}",
            f"  calls: {', '.join(self.calls[:12]) or 'none'}",
            f"  authorization checks: {', '.join(self.authorization_checks) or 'NONE FOUND'}",
            f"  state changes: {', '.join(self.state_changes) or 'none'}",
            f"  audit writes: {', '.join(self.audit_writes) or 'NONE FOUND'}",
            f"  threshold comparisons: "
            f"{', '.join(self.threshold_comparisons) or 'NONE FOUND'}",
            f"  conditionals: {self.conditionals}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "function": self.function, "file": self.file, "line": self.line,
            "language": self.language, "parameters": self.parameters,
            "calls": self.calls[:20],
            "authorization_checks": self.authorization_checks,
            "state_changes": self.state_changes,
            "audit_writes": self.audit_writes,
            "threshold_comparisons": self.threshold_comparisons,
            "conditionals": self.conditionals,
            "crypto_operations": self.crypto_operations,
        }


class BusinessIntentEngine(BaseEngine):
    """Requirements-vs-behaviour analysis, grounded in the UST."""

    name = ENGINE_NAME

    def __init__(self, *, reasoning_service=None, knowledge_retriever=None,
                 extractor: Optional[PolicyExtractor] = None,
                 use_llm: bool = True) -> None:
        self.service = reasoning_service
        self.knowledge = knowledge_retriever
        self.extractor = extractor or PolicyExtractor()
        self.use_llm = use_llm

    # ------------------------------------------------------------------
    def analyze(self, context: AnalysisContext) -> EngineResult:
        sources = list(context.business_requirements)
        if not sources:
            return EngineResult(output={
                "status": "no_requirements",
                "message": ("No business requirement documents supplied. "
                            "Business-intent analysis needs requirements to compare "
                            "the code against."),
                "policies": [], "verdicts": []})

        policy_set = self.extractor.extract_from_sources(sources)
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        verdicts: list[dict] = []

        checkable = policy_set.checkable
        log.info("business intent: %d policies (%d checkable) from %d document(s)",
                 len(policy_set), len(checkable), len(sources))

        for policy in checkable:
            implementations = self._find_implementations(context, policy)
            policy_evidence = self._policy_evidence(policy, implementations, context)
            # Publish now so the contextual pass below can select by ID.
            # `EvidenceStore.add` is idempotent by fingerprint, so the
            # pipeline's own publication in `run_engine` is a no-op for these.
            policy_evidence = [context.evidence.add(item) for item in policy_evidence]
            evidence.extend(policy_evidence)

            if not implementations:
                verdicts.append(self._unimplemented_verdict(policy))
                continue

            deterministic, deterministic_findings = self._deterministic_verdict(
                policy, implementations, policy_evidence, context)
            verdicts.append(deterministic)
            findings.extend(deterministic_findings)

        # Contextual pass over the cases deterministic analysis flagged.
        ai_findings, ai_verdicts = self._contextual_pass(
            context, policy_set, verdicts, evidence)
        findings.extend(ai_findings)

        return EngineResult(
            evidence=evidence, findings=findings,
            output={
                "status": "analyzed",
                "documents": policy_set.documents,
                "policies": policy_set.to_dict(),
                "verdicts": verdicts,
                "ai": ai_verdicts,
                "alignment_score": _alignment_score(verdicts),
            })

    # ------------------------------------------------------------------
    # Locating implementations
    # ------------------------------------------------------------------
    def _find_implementations(self, context: AnalysisContext,
                              policy: BusinessPolicy) -> list[BehaviorProfile]:
        """Find functions that plausibly implement `policy`, ranked by match."""
        terms = policy.search_terms()
        if not terms:
            return []

        scored: list[tuple[float, BehaviorProfile]] = []
        for ust_file in context.ust:
            for function in ust_file.functions():
                score = _match_score(function, terms, policy)
                if score <= 0:
                    continue
                scored.append((score, self._profile(function, ust_file)))

        scored.sort(key=lambda pair: -pair[0])
        return [profile for _, profile in scored[:MAX_IMPLEMENTATIONS_PER_POLICY]]

    def _profile(self, function: USTNode, ust_file: USTFile) -> BehaviorProfile:
        """Read one function's behaviour out of the UST."""
        profile = BehaviorProfile(
            function=function.name, file=ust_file.path, language=ust_file.language,
            line=function.line, end_line=function.span.end_line,
            parameters=list(function.parameters))

        body = [n for n in ust_file.nodes
                if n is not function and n.enclosing_function == function.name]

        for node in body:
            if node.type is USTNodeType.CONDITIONAL:
                profile.conditionals += 1
                continue
            symbol = node.symbol or node.name
            if not symbol:
                continue
            if node.type in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION,
                             USTNodeType.AUTHORIZATION_CHECK,
                             USTNodeType.DATABASE_OPERATION):
                profile.calls.append(symbol)
                if "authorization_check" in node.business_tags:
                    profile.authorization_checks.append(symbol)
                if AUDIT_WRITE.search(symbol) or AUDIT_WRITE.search(
                        " ".join(node.arguments)):
                    profile.audit_writes.append(symbol)
                elif STATE_CHANGE.search(symbol) or "database_operation" in node.business_tags:
                    profile.state_changes.append(symbol)
                if node.crypto_tags:
                    profile.crypto_operations.append(symbol)
                if re.search(r"(?i)(rate.?limit|throttl|quota|bucket|limiter)", symbol):
                    profile.rate_limit_markers.append(symbol)
                if re.search(r"(?i)(validate|verify|check|assert|require|ensure|"
                             r"sanitiz|sanitis|is_valid)", symbol):
                    profile.validation_calls.append(symbol)

        # Annotations can carry the control (@PreAuthorize, @RolesAllowed, @login_required)
        for node in ust_file.of_type(USTNodeType.ANNOTATION):
            if abs(node.line - function.line) > 3:
                continue
            if re.search(r"(?i)(preauthorize|secured|rolesallowed|login_required|"
                         r"permission_required|authorize|requires_auth|guard)", node.name):
                profile.authorization_checks.append(f"@{node.name}")
            if re.search(r"(?i)(ratelimit|rate_limit|throttle)", node.name):
                profile.rate_limit_markers.append(f"@{node.name}")

        profile.threshold_comparisons = self._threshold_comparisons(function, ust_file)
        # de-duplicate while keeping order
        for attribute in ("calls", "authorization_checks", "state_changes",
                          "audit_writes", "crypto_operations", "rate_limit_markers",
                          "validation_calls"):
            setattr(profile, attribute, list(dict.fromkeys(getattr(profile, attribute))))
        return profile

    @staticmethod
    def _threshold_comparisons(function: USTNode, ust_file: USTFile) -> list[str]:
        """Numeric comparisons inside the function — the shape a threshold
        rule takes in code. Read from the conditional's own source line, so
        this works identically for `if amount > 50000` in any language."""
        out: list[str] = []
        for node in ust_file.nodes:
            if node.type is not USTNodeType.CONDITIONAL:
                continue
            if node.enclosing_function != function.name:
                continue
            match = re.search(r"([A-Za-z_][\w.]*)\s*(>=|<=|>|<|==)\s*([\d_,]+(?:\.\d+)?)",
                              node.snippet)
            if match:
                out.append(f"{match.group(1)} {match.group(2)} {match.group(3)}")
        return out

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------
    def _policy_evidence(self, policy: BusinessPolicy,
                         implementations: list[BehaviorProfile],
                         context: AnalysisContext) -> list[Evidence]:
        evidence: list[Evidence] = [Evidence(
            type=EvidenceType.BUSINESS_POLICY,
            source="policy_extractor",
            file=policy.source_document,
            symbol=policy.action,
            operation=f"business policy: {policy.plain_english()}",
            description=policy.source_text,
            confidence=1.0,
            tags=["policy", policy.required_control.value, policy.policy_id],
            metadata={"policy_id": policy.policy_id,
                      "action": policy.action,
                      "required_control": policy.required_control.value,
                      "condition": policy.condition.describe()},
        )]

        for profile in implementations:
            evidence.append(Evidence(
                type=EvidenceType.BEHAVIOR,
                source=DETECTOR,
                file=profile.file, line=profile.line, end_line=profile.end_line,
                language=profile.language, symbol=profile.function,
                operation=f"observed behaviour of {profile.function}()",
                description=profile.describe(),
                confidence=0.95,
                tags=["behavior", policy.policy_id, policy.action],
                metadata={"policy_id": policy.policy_id, **profile.to_dict()},
            ))

            if not profile.has_control(policy.required_control):
                evidence.append(Evidence(
                    type=EvidenceType.MISSING_CONTROL,
                    source=DETECTOR,
                    file=profile.file, line=profile.line, end_line=profile.end_line,
                    language=profile.language, symbol=profile.function,
                    operation=(f"no {policy.required_control.value} control found in "
                               f"{profile.function}()"),
                    description=(
                        f"Policy {policy.policy_id} requires "
                        f"{policy.control_detail or policy.required_control.value}, but "
                        f"{profile.function}() at {profile.file}:{profile.line} contains no "
                        f"such control on the path to its state changes "
                        f"({', '.join(profile.state_changes) or 'none observed'})."),
                    confidence=0.85,
                    severity_hint=_severity_for(policy),
                    tags=["missing_control", policy.required_control.value,
                          policy.policy_id],
                    metadata={"policy_id": policy.policy_id,
                              "required_control": policy.required_control.value,
                              "function": profile.function},
                ))

            if policy.condition.is_threshold and not profile.threshold_comparisons:
                evidence.append(Evidence(
                    type=EvidenceType.MISSING_CONTROL,
                    source=DETECTOR,
                    file=profile.file, line=profile.line,
                    language=profile.language, symbol=profile.function,
                    operation=(f"no threshold comparison on "
                               f"'{policy.condition.field}' in {profile.function}()"),
                    description=(
                        f"Policy {policy.policy_id} applies when "
                        f"{policy.condition.describe()}, but {profile.function}() contains "
                        f"no numeric comparison implementing that threshold."),
                    confidence=0.8,
                    severity_hint=_severity_for(policy),
                    tags=["missing_threshold", policy.policy_id],
                    metadata={"policy_id": policy.policy_id,
                              "expected_condition": policy.condition.describe()},
                ))
        return evidence

    # ------------------------------------------------------------------
    # Deterministic verdicts
    # ------------------------------------------------------------------
    def _deterministic_verdict(self, policy: BusinessPolicy,
                               implementations: list[BehaviorProfile],
                               evidence: list[Evidence],
                               context: AnalysisContext) -> tuple[dict, list[Finding]]:
        missing = [p for p in implementations if not p.has_control(policy.required_control)]
        satisfied = [p for p in implementations if p.has_control(policy.required_control)]

        findings: list[Finding] = []
        if not missing:
            verdict = ComplianceVerdict.COMPLIANT
        elif satisfied:
            # Some paths implement it and some do not — a genuine ambiguity
            # that deterministic analysis should not resolve on its own.
            verdict = ComplianceVerdict.POTENTIAL_VIOLATION
        else:
            verdict = ComplianceVerdict.VIOLATION

        if verdict is ComplianceVerdict.VIOLATION:
            profile = missing[0]
            evidence_ids = [e.fingerprint for e in evidence
                            if (e.metadata or {}).get("policy_id") == policy.policy_id
                            and e.type in (EvidenceType.MISSING_CONTROL,
                                           EvidenceType.BEHAVIOR,
                                           EvidenceType.BUSINESS_POLICY)]
            findings.append(Finding(
                category="Business Intent Violation",
                severity=_severity_for(policy),
                rule_id=f"BI-{policy.required_control.value.upper()[:6]}-001",
                file=profile.file,
                line=profile.line,
                snippet=f"{profile.function}({', '.join(profile.parameters)})",
                recommendation=(
                    f"Implement {policy.control_detail or policy.required_control.value} in "
                    f"{profile.function}() before its state-changing operations "
                    f"({', '.join(profile.state_changes) or 'the persistence call'}). "
                    f"Requirement: \"{policy.source_text[:160]}\""),
                cwe="CWE-285" if policy.required_control is ControlType.AUTHORIZATION else None,
                owasp="A01:2021" if policy.required_control is ControlType.AUTHORIZATION else None,
                confidence=0.8,
                language=profile.language,
                function=profile.function,
                evidence_ids=evidence_ids,
                source="DETERMINISTIC",
                reason=(f"Policy {policy.policy_id} requires "
                        f"{policy.control_detail or policy.required_control.value} for "
                        f"'{policy.action}', but {profile.function}() at {profile.file}:"
                        f"{profile.line} implements '{policy.action}' with no such control."),
                engine=self.name,
            ))

        return ({
            "policy_id": policy.policy_id,
            "policy": policy.plain_english(),
            "requirement": policy.source_text,
            "verdict": verdict.value,
            "source": "DETERMINISTIC",
            "implementations": [p.to_dict() for p in implementations],
            "missing_control_in": [p.function for p in missing],
            "satisfied_in": [p.function for p in satisfied],
        }, findings)

    @staticmethod
    def _unimplemented_verdict(policy: BusinessPolicy) -> dict:
        return {
            "policy_id": policy.policy_id,
            "policy": policy.plain_english(),
            "requirement": policy.source_text,
            "verdict": ComplianceVerdict.INSUFFICIENT_EVIDENCE.value,
            "source": "DETERMINISTIC",
            "implementations": [],
            "note": ("No function implementing this action was found in the parsed "
                     "code. The requirement may be unimplemented, implemented in an "
                     "unsupported language, or named differently."),
        }

    # ------------------------------------------------------------------
    # Contextual (Nemotron) pass
    # ------------------------------------------------------------------
    def _contextual_pass(self, context: AnalysisContext, policy_set: PolicySet,
                         verdicts: list[dict],
                         evidence: list[Evidence]) -> tuple[list[Finding], dict]:
        if not self.use_llm or self.service is None:
            return [], {"status": "skipped", "reason": "contextual analysis disabled"}
        if not self.service.configured:
            return [], {"status": "unavailable",
                        "reason": self.service.unavailable_reason()}

        # Only ambiguous cases are worth a model call — a policy with no
        # implementation has nothing to reason about, and a clean COMPLIANT
        # verdict costs tokens to re-confirm.
        interesting = [v for v in verdicts
                       if v["verdict"] in (ComplianceVerdict.VIOLATION.value,
                                           ComplianceVerdict.POTENTIAL_VIOLATION.value)]
        if not interesting:
            return [], {"status": "no_candidates"}

        all_findings: list[Finding] = []
        reports: list[dict] = []

        for verdict in interesting[:10]:
            policy = policy_set.get(verdict["policy_id"])
            if policy is None:
                continue
            policy_evidence = [e for e in context.evidence
                               if (e.metadata or {}).get("policy_id") == policy.policy_id]
            if not policy_evidence:
                continue

            findings, report = self._reason_about_policy(context, policy, policy_evidence)
            all_findings.extend(findings)
            reports.append(report)

        return all_findings, {"status": "analyzed", "reports": reports}

    def _reason_about_policy(self, context: AnalysisContext, policy: BusinessPolicy,
                             policy_evidence: list[Evidence]) -> tuple[list[Finding], dict]:
        knowledge_block = ""
        knowledge_meta: dict = {}
        if self.knowledge is not None:
            retrieval = self.knowledge.retrieve_for_evidence(
                policy_evidence,
                extra_terms=[policy.required_control.value, policy.action,
                             "business rule", "compliance"])
            knowledge_block = retrieval.render()
            knowledge_meta = retrieval.to_dict()

        behaviour = next((e for e in policy_evidence
                          if e.type is EvidenceType.BEHAVIOR), None)
        ust_block = ""
        if behaviour is not None:
            ust_block = render_ust_context(
                context.ust_file(behaviour.file),
                around_line=behaviour.line, function_name=behaviour.symbol)

        request = ReasoningRequest(
            task="business_intent",
            instruction=(
                "Decide whether the code satisfies the business policy below.\n"
                f"POLICY: {policy.plain_english()}\n"
                f"REQUIREMENT AS WRITTEN: \"{policy.source_text}\"\n"
                f"REQUIRED CONTROL: {policy.required_control.value}"
                f" ({policy.control_detail})\n"
                + (f"CONDITION: {policy.condition.describe()}\n"
                   if policy.condition.is_threshold else "")
                + "\nJudge only from the EVIDENCE and CODE STRUCTURE below. "
                  "Return VIOLATION only when the evidence shows the required control "
                  "is absent from the path that performs the action. Return "
                  "INSUFFICIENT_EVIDENCE when you cannot tell."),
            schema_instruction=BUSINESS_INTENT_SCHEMA_INSTRUCTION,
            evidence_block=render_evidence(policy_evidence),
            knowledge_block=knowledge_block,
            business_block=f"POLICIES:\n- {policy.to_context_line()}",
            ust_block=ust_block,
            cache_key_extra=policy.policy_id,
        )

        result = self.service.reason(request)
        report = {
            "policy_id": policy.policy_id,
            "available": result.available,
            "error": result.error,
            "cached": result.cached,
            "prompt_chars": result.prompt_chars,
            "knowledge": knowledge_meta,
        }
        if not result.available or result.response is None:
            report["status"] = "unavailable"
            return [], report

        validator = AIFindingValidator(
            context, allowed_evidence={e.id for e in policy_evidence if e.id})
        validation = validator.validate_response(result.response)
        report["validation"] = validation.to_dict()

        accepted = [f for f in validation.accepted
                    if str(f.metadata.get("verdict", "")) in
                    (ComplianceVerdict.VIOLATION.value,
                     ComplianceVerdict.POTENTIAL_VIOLATION.value)]
        for item in accepted:
            item.category = "Business Intent Violation"
            item.metadata.setdefault("policy_id", policy.policy_id)
            item.metadata.setdefault("requirement", policy.source_text)

        report["status"] = "analyzed"
        return to_findings(accepted, engine=self.name,
                           default_category="Business Intent Violation"), report


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _match_score(function: USTNode, terms: list[str], policy: BusinessPolicy) -> float:
    """How strongly a function looks like this policy's implementation."""
    name = (function.name or "").lower()
    symbol = (function.symbol or "").lower()
    if not name:
        return 0.0
    # split camelCase / snake_case into comparable tokens
    tokens = set(re.findall(r"[a-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_",
                                                 function.name or "").lower()))
    tokens |= set(re.findall(r"[a-z0-9]+", (function.enclosing_class or "").lower()))

    score = 0.0
    for term in terms:
        if term in tokens:
            score += 3.0
        elif term in name or term in symbol:
            score += 1.5
    if policy.action.lower() in tokens:
        score += 2.0            # the action verb itself is the strongest signal
    for tag in function.business_tags:
        if tag in terms:
            score += 1.0
    return score


def _severity_for(policy: BusinessPolicy) -> str:
    return {
        "Critical": Severity.CRITICAL.value,
        "High": Severity.HIGH.value,
        "Medium": Severity.MEDIUM.value,
        "Low": Severity.LOW.value,
    }.get(policy.priority.value, Severity.MEDIUM.value)


def _alignment_score(verdicts: list[dict]) -> float:
    """0-100 alignment between requirements and code.

    Policies with no located implementation are excluded rather than
    counted as violations — "we could not find it" is not "it is broken",
    and conflating them makes the score meaningless on partial scans.
    """
    judged = [v for v in verdicts
              if v["verdict"] != ComplianceVerdict.INSUFFICIENT_EVIDENCE.value]
    if not judged:
        return 100.0
    weights = {
        ComplianceVerdict.COMPLIANT.value: 1.0,
        ComplianceVerdict.POTENTIAL_VIOLATION.value: 0.5,
        ComplianceVerdict.VIOLATION.value: 0.0,
    }
    total = sum(weights.get(v["verdict"], 0.5) for v in judged)
    return round(100.0 * total / len(judged), 2)
