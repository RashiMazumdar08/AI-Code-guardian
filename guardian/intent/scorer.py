"""
Scorer Module for Business Intent Engine
=======================================
Calculates overall business alignment score (%) and totals.
"""
from __future__ import annotations

from typing import Any


class AlignmentScorer:
    """Calculates alignment metrics for business intent evaluation."""

    def score(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        if not findings:
            return {
                "alignment_score": 1.0,
                "alignment_percentage": 100,
                "total_rules": 0,
                "matched": 0,
                "violated": 0,
                "partial": 0,
                "insufficient": 0,
            }

        total_rules = len(findings)
        violated = sum(1 for f in findings if f.get("status") == "VIOLATION")
        matched = sum(1 for f in findings if f.get("status") == "COMPLIANT")
        partial = sum(1 for f in findings if f.get("status") == "PARTIAL")
        # NOTE: RuleMatcher emits the status string "INSUFFICIENT_EVIDENCE",
        # never the bare "INSUFFICIENT" — this previously undercounted
        # `insufficient` (often to 0 even when every rule was genuinely
        # insufficient), which in turn made engine.py's "all rules
        # insufficient -> overall INSUFFICIENT_EVIDENCE" case nearly
        # unreachable and silently fell through to a fabricated "SUCCESS".
        insufficient = sum(1 for f in findings if f.get("status") == "INSUFFICIENT_EVIDENCE")

        # Alignment calculation formula
        weighted_score = (matched * 1.0) + (partial * 0.5) + (insufficient * 0.25)
        raw_score = max(0.0, min(1.0, weighted_score / total_rules)) if total_rules > 0 else 1.0
        percentage = round(raw_score * 100, 1)

        return {
            "alignment_score": round(raw_score, 2),
            "alignment_percentage": percentage,
            "total_rules": total_rules,
            "matched": matched,
            "violated": violated,
            "partial": partial,
            "insufficient": insufficient,
        }
