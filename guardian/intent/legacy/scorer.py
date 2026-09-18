"""
Business Intent Engine — Scorer (v4 Enhanced)
===============================================
Changes from v3:
- to_findings() uses RuleMatch.human_summary as the snippet (readable in dashboard)
- recommendation field is a clean developer-facing message (not raw gap text)
- Each finding includes impact_statement in the recommendation block
- Priority weighting: VIOLATED > NOT_IMPLEMENTED High > NOT_IMPLEMENTED Medium > PARTIAL
"""
from __future__ import annotations

from guardian.intent.legacy.models import (
    BusinessAlignmentReport, MatchStatus, RuleMatch, Requirement
)
from guardian.core.models import Finding, Severity


class BusinessIntentScorer:

    def __init__(
        self,
        weight_semantic:      float = 0.40,
        weight_coverage:      float = 0.35,
        weight_no_violations: float = 0.25,
    ):
        self.weight_semantic      = weight_semantic
        self.weight_coverage      = weight_coverage
        self.weight_no_violations = weight_no_violations

    # ──────────────────────────────────────────────────────────────────
    # Core scoring
    # ──────────────────────────────────────────────────────────────────

    def score(
        self,
        matches: list[RuleMatch],
        requirements: list[Requirement] | None = None,
    ) -> BusinessAlignmentReport:

        if not matches:
            return BusinessAlignmentReport(
                alignment_score=100.0, rule_coverage=1.0,
                total_rules=0, matched=0, partial=0, not_implemented=0, violated=0,
            )

        total     = len(matches)
        matched   = sum(1 for m in matches if m.status == MatchStatus.MATCHED)
        partial   = sum(1 for m in matches if m.status == MatchStatus.PARTIAL)
        not_impl  = sum(1 for m in matches if m.status == MatchStatus.NOT_IMPLEMENTED)
        violated  = sum(1 for m in matches if m.status == MatchStatus.VIOLATED)

        semantic    = (matched + partial * 0.5) / total
        coverage    = (matched + partial) / total
        no_viol     = 0.0 if violated > 0 else 1.0

        alignment = (
            semantic   * self.weight_semantic
            + coverage * self.weight_coverage
            + no_viol  * self.weight_no_violations
        ) * 100

        missing = [m.rule for m in matches if m.status == MatchStatus.NOT_IMPLEMENTED]

        return BusinessAlignmentReport(
            alignment_score=round(alignment, 2),
            rule_coverage=round(1.0 - not_impl / total, 3),
            total_rules=total,
            matched=matched,
            partial=partial,
            not_implemented=not_impl,
            violated=violated,
            matches=matches,
            missing_rules=missing,
        )

    # ──────────────────────────────────────────────────────────────────
    # Convert to Finding objects
    # ──────────────────────────────────────────────────────────────────

    def to_findings(self, report: BusinessAlignmentReport) -> list[Finding]:
        findings: list[Finding] = []

        for match in report.matches:
            if match.status == MatchStatus.MATCHED:
                continue

            severity = self._severity(match)
            rec      = self._recommendation(match)

            findings.append(Finding(
                category="Business Intent",
                severity=severity,
                rule_id=f"BIZ-{match.rule.rule_id[:8].upper()}",
                file=match.matched_artefact or "<codebase>",
                line=0,
                # Human-readable snippet: what rule is violated in plain English
                snippet=match.rule.plain_english[:200],
                recommendation=rec,
                cwe=None,
                owasp=None,
                confidence=match.confidence,
                tainted=False,
            ))

        # Sort: VIOLATED first, then NOT_IMPLEMENTED High, then the rest
        priority_order = {
            MatchStatus.VIOLATED:         0,
            MatchStatus.NOT_IMPLEMENTED:  1,
            MatchStatus.PARTIAL:          2,
        }
        findings.sort(key=lambda f: (
            priority_order.get(
                next((m.status for m in report.matches
                      if m.matched_artefact == f.file and
                         m.rule.plain_english == f.snippet), MatchStatus.PARTIAL),
                9
            ),
            f.severity
        ))

        return findings

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _severity(match: RuleMatch) -> str:
        if match.status == MatchStatus.VIOLATED:
            return Severity.CRITICAL.value
        if match.status == MatchStatus.NOT_IMPLEMENTED:
            return Severity.HIGH.value if match.rule.priority == "High" else Severity.MEDIUM.value
        return Severity.MEDIUM.value if match.rule.priority == "High" else Severity.LOW.value

    @staticmethod
    def _recommendation(match: RuleMatch) -> str:
        """
        Assembles a concise, developer-facing recommendation block.
        Format:
          WHAT:   one sentence from human_summary
          WHY:    impact_statement
          HOW:    numbered fix_steps
        """
        lines = [
            f"WHAT: {match.human_summary}",
        ]
        if match.impact_statement:
            lines.append(f"WHY:  {match.impact_statement}")
        if match.fix_steps:
            lines.append("HOW:")
            for i, step in enumerate(match.fix_steps, 1):
                lines.append(f"  {i}. {step}")
        lines.append(
            f"SOURCE REQUIREMENT: {match.rule.requirement_id} — \"{match.rule.source_text[:120]}\""
        )
        return "\n".join(lines)
