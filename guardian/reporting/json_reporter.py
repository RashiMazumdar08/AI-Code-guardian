"""JSON reporter — the canonical machine-readable report."""
from __future__ import annotations

import json

from guardian.core.registry import register_reporter
from guardian.reporting._shared import normalize_for_display


@register_reporter
class JsonReporter:
    name = "json"
    file_extension = ".json"

    def render(self, report: dict) -> str:
        # normalize_for_display() strips the not-yet-implemented Quantum
        # Readiness dimension and overwrites unified_risk.alignment_score
        # with the live Business Intent Engine value, so this "canonical"
        # export can't disagree with what the app itself shows -- see
        # guardian/reporting/_shared.py for the full rationale.
        return json.dumps(normalize_for_display(report), indent=2, default=str)
