"""
Business Intent Engine — Data Models (v4 Enhanced)
====================================================
Added:
  - BusinessRule.plain_english   human-readable sentence summary
  - RuleMatch.human_summary      one-line plain-English verdict
  - RuleMatch.fix_steps          numbered list of concrete fix actions
  - RuleMatch.impact_statement   business consequence if gap is not fixed
  - BusinessAlignmentReport.narrative  overall story summary for dashboard
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class MatchStatus(str, Enum):
    MATCHED          = "Matched"
    PARTIAL          = "Partially Matched"
    NOT_IMPLEMENTED  = "Not Implemented"
    VIOLATED         = "Violated"


class RuleType(str, Enum):
    AUTHORIZATION  = "Authorization"
    VALIDATION     = "Validation"
    WORKFLOW       = "Workflow"
    DATA_CONSTRAINT = "Data Constraint"
    API_CONTRACT   = "API Contract"
    AUDIT          = "Audit"
    RATE_LIMIT     = "Rate Limit"
    GENERAL        = "General"


@dataclass
class BusinessRule:
    """
    A structured business rule extracted from a requirement document.

    Actor → Action → Condition → Expected Outcome

    New in v4:
      plain_english  — one sentence a developer can read immediately,
                       e.g. "Only managers may approve loans above ₹10 lakh."
    """
    requirement_id:   str
    actor:            str
    action:           str
    condition:        str
    expected_outcome: str
    rule_type:        RuleType = RuleType.GENERAL
    priority:         str      = "High"
    source_text:      str      = ""
    plain_english:    str      = ""     # ← NEW: human-readable sentence
    rule_id:          str      = field(default="", init=False)

    def __post_init__(self):
        basis = f"{self.requirement_id}:{self.actor}:{self.action}:{self.condition}"
        self.rule_id = hashlib.sha256(basis.encode()).hexdigest()[:12]
        if not self.plain_english:
            self.plain_english = self._build_plain_english()

    def _build_plain_english(self) -> str:
        parts = []
        if self.actor and self.actor != "system":
            parts.append(f"Only {self.actor}s")
        else:
            parts.append("The system")
        parts.append(f"may {self.action}")
        if self.condition:
            parts.append(f"when {self.condition}")
        outcome = self.expected_outcome.lower()
        if "denied" in outcome or "blocked" in outcome:
            parts = [f"{self.actor.capitalize()} must NOT {self.action}"]
            if self.condition:
                parts.append(f"when {self.condition}")
        elif "audit" in outcome or "log" in outcome:
            parts = [f"Every {self.action} by {self.actor} must be audit-logged"]
        return " ".join(parts).rstrip(".") + "."

    def to_dict(self) -> dict:
        d = asdict(self)
        d["rule_id"]       = self.rule_id
        d["plain_english"] = self.plain_english
        return d


@dataclass
class Requirement:
    source_id:          str
    source_type:        str
    title:              str
    content:            str
    acceptance_criteria: list[str] = field(default_factory=list)
    tags:               list[str]  = field(default_factory=list)
    metadata:           dict       = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuleMatch:
    """
    Result of matching a BusinessRule against a code artefact.

    New in v4:
      human_summary    — one plain-English sentence: what happened and why it matters
      fix_steps        — numbered list of concrete actions to resolve the gap
      impact_statement — business/compliance consequence if this gap reaches production
    """
    rule:             BusinessRule
    matched_artefact: str
    status:           MatchStatus
    confidence:       float
    evidence:         str
    gap_description:  str         = ""
    human_summary:    str         = field(default="", init=False)   # ← NEW
    fix_steps:        list[str]   = field(default_factory=list)     # ← NEW
    impact_statement: str         = ""                               # ← NEW

    def __post_init__(self):
        self.human_summary = self._build_human_summary()
        if not self.fix_steps:
            self.fix_steps = self._build_fix_steps()
        if not self.impact_statement:
            self.impact_statement = self._build_impact()

    # ------------------------------------------------------------------ #
    # Plain-English summary builders
    # ------------------------------------------------------------------ #

    def _build_human_summary(self) -> str:
        rule   = self.rule
        status = self.status

        if status == MatchStatus.MATCHED:
            return (
                f"✅ '{rule.plain_english}' is correctly implemented in "
                f"{self.matched_artefact or 'the codebase'}."
            )
        if status == MatchStatus.VIOLATED:
            return (
                f"🚨 VIOLATION — The code in {self.matched_artefact} actively bypasses "
                f"the rule that {rule.plain_english} "
                f"This creates a security hole that an attacker could exploit directly."
            )
        if status == MatchStatus.NOT_IMPLEMENTED:
            return (
                f"❌ Missing implementation — The rule '{rule.plain_english}' "
                f"was required by story {rule.requirement_id} but no matching "
                f"code was found. The feature is incomplete."
            )
        # PARTIAL
        return (
            f"⚠️  Partial implementation — The code in {self.matched_artefact} "
            f"partially addresses '{rule.plain_english}' but the "
            f"{self._gap_label()} guard is missing."
        )

    def _gap_label(self) -> str:
        rt = self.rule.rule_type
        labels = {
            RuleType.AUTHORIZATION:  "role/permission check",
            RuleType.VALIDATION:     "input validation",
            RuleType.AUDIT:          "audit logging",
            RuleType.WORKFLOW:       "workflow step",
            RuleType.DATA_CONSTRAINT:"constraint enforcement",
        }
        return labels.get(rt, "enforcement")

    def _build_fix_steps(self) -> list[str]:
        rule = self.rule
        rt   = rule.rule_type
        status = self.status

        if status == MatchStatus.MATCHED:
            return ["No action required."]

        steps: list[str] = []

        if status == MatchStatus.VIOLATED:
            steps.append(
                f"Remove or correct the authentication bypass in {self.matched_artefact} "
                f"(look for 'return true', 'skipAuth', or 'trustAllCerts' patterns)."
            )
            steps.append("Add the required role or permission check before the operation executes.")
            steps.append(f"Add a unit test that verifies a non-{rule.actor} user receives a 403 Forbidden.")
            return steps

        if rt == RuleType.AUTHORIZATION:
            steps.append(
                f"Add a role check so only '{rule.actor}' users can perform '{rule.action}'. "
                f"In Spring use @PreAuthorize(\"hasRole('{rule.actor.upper()}')\"); "
                f"in plain Java call SecurityContext.getAuthorities() before the operation."
            )
            steps.append(
                f"Make sure the check fires before any database or business-logic call, "
                f"not after."
            )
            steps.append(
                f"Write a test: call the endpoint as a non-{rule.actor} user and assert HTTP 403."
            )

        elif rt == RuleType.VALIDATION:
            steps.append(
                f"Add input validation for '{rule.action}'. "
                f"Use @Valid + @NotNull / @Min / @Max on the request DTO, or call "
                f"Objects.requireNonNull() / Preconditions.checkArgument() at the top of the method."
            )
            if rule.condition:
                steps.append(
                    f"Enforce the specific constraint: '{rule.condition}'. "
                    f"Throw an IllegalArgumentException or a domain-specific exception if violated."
                )
            steps.append("Add a negative test that sends an invalid value and asserts a 400 Bad Request.")

        elif rt == RuleType.AUDIT:
            steps.append(
                f"Log every '{rule.action}' event. "
                f"Call auditLog.record() or log.info() with the actor ID, action name, "
                f"timestamp, and outcome immediately after the operation succeeds."
            )
            steps.append("Ensure PII fields (passwords, card numbers) are masked in the log entry.")
            steps.append("Add a test that performs the action and asserts the audit table or log contains a new entry.")

        elif rt == RuleType.WORKFLOW:
            steps.append(
                f"Ensure the '{rule.action}' step is present in the workflow and only "
                f"reachable when the precondition '{rule.condition}' is met."
            )
            steps.append("Add a state machine check or explicit status guard before executing the step.")

        else:
            steps.append(
                f"Implement the missing business rule: {rule.plain_english}"
            )
            steps.append(
                f"Trace story {rule.requirement_id} and add the required logic to "
                f"{self.matched_artefact or 'the appropriate service class'}."
            )

        if not any("test" in s.lower() for s in steps):
            steps.append(
                f"Add a unit test covering the happy path and at least one edge case "
                f"for '{rule.action}'."
            )

        return steps

    def _build_impact(self) -> str:
        rule   = self.rule
        rt     = rule.rule_type
        status = self.status

        if status == MatchStatus.MATCHED:
            return ""

        if status == MatchStatus.VIOLATED:
            return (
                f"Critical business risk: the bypass means any user can perform "
                f"'{rule.action}' regardless of their role. In a financial system "
                f"this could allow unauthorised transactions. Regulatory frameworks "
                f"(PCI-DSS, RBI) require access controls to be enforced."
            )

        impacts = {
            RuleType.AUTHORIZATION: (
                f"Without the role check, any authenticated user (not just {rule.actor}s) "
                f"can trigger '{rule.action}'. This violates least-privilege and may "
                f"breach compliance requirements."
            ),
            RuleType.VALIDATION: (
                f"Without input validation, the system accepts out-of-range or malformed data "
                f"for '{rule.action}', which can corrupt the database or trigger business logic "
                f"errors (e.g. negative amounts, oversized transfers)."
            ),
            RuleType.AUDIT: (
                f"Without an audit trail for '{rule.action}', the system cannot detect fraud, "
                f"support forensic investigation, or satisfy audit requirements under "
                f"PCI-DSS / RBI guidelines."
            ),
            RuleType.WORKFLOW: (
                f"The workflow step '{rule.action}' may execute out of sequence, "
                f"bypassing dependent checks and leading to data integrity failures."
            ),
        }
        return impacts.get(
            rt,
            f"The requirement '{rule.requirement_id}' is not satisfied. "
            f"This gap may cause incorrect behaviour in production."
        )

    def to_dict(self) -> dict:
        return {
            "rule":             self.rule.to_dict(),
            "matched_artefact": self.matched_artefact,
            "status":           self.status.value,
            "confidence":       self.confidence,
            "evidence":         self.evidence,
            "gap_description":  self.gap_description,
            "human_summary":    self.human_summary,
            "fix_steps":        self.fix_steps,
            "impact_statement": self.impact_statement,
        }


@dataclass
class BusinessAlignmentReport:
    alignment_score:  float
    rule_coverage:    float
    total_rules:      int
    matched:          int
    partial:          int
    not_implemented:  int
    violated:         int
    matches:          list[RuleMatch] = field(default_factory=list)
    missing_rules:    list[BusinessRule] = field(default_factory=list)
    narrative:        str = field(default="", init=False)   # ← NEW

    def __post_init__(self):
        self.narrative = self._build_narrative()

    def _build_narrative(self) -> str:
        t = self.total_rules
        if t == 0:
            return "No business rules were extracted from the requirements."

        pct = round(self.alignment_score)
        lines = []

        if pct >= 90:
            lines.append(
                f"✅ Strong alignment ({pct}%). The code implements "
                f"{self.matched} of {t} business rules correctly."
            )
        elif pct >= 65:
            lines.append(
                f"⚠️  Moderate alignment ({pct}%). {self.matched} rules are fully "
                f"implemented, {self.partial} are partial, and {self.not_implemented} "
                f"are missing."
            )
        else:
            lines.append(
                f"❌ Poor alignment ({pct}%). Only {self.matched} of {t} business "
                f"rules are implemented. {self.not_implemented} rules are completely "
                f"absent from the codebase."
            )

        if self.violated > 0:
            lines.append(
                f"🚨 {self.violated} rule(s) are actively VIOLATED — the code "
                f"contradicts what the business story requires. These are the "
                f"highest-priority issues to fix."
            )

        if self.not_implemented > 0:
            top_missing = [r.plain_english for r in self.missing_rules[:3]]
            lines.append(
                f"Top missing rules: {'; '.join(top_missing)}."
            )

        return " ".join(lines)

    def to_dict(self) -> dict:
        return {
            "alignment_score":  round(self.alignment_score, 2),
            "rule_coverage":    round(self.rule_coverage, 3),
            "total_rules":      self.total_rules,
            "matched":          self.matched,
            "partial":          self.partial,
            "not_implemented":  self.not_implemented,
            "violated":         self.violated,
            "narrative":        self.narrative,
            "missing_rules":    [r.to_dict() for r in self.missing_rules],
            "matches":          [m.to_dict() for m in self.matches],
        }
