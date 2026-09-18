"""
CSV Reporter — tabular export for Security Operations Centers and SIEM tools.

Carries the provenance columns added by the UST/evidence refactor so a
downstream system can filter deterministic detections from contextual AI
findings without re-deriving that from free text.
"""
from __future__ import annotations

import csv
import io

from guardian.core.registry import register_reporter
from guardian.reporting._shared import visible_findings

COLUMNS = [
    "Finding ID", "Rule ID", "Category", "Severity", "Source", "Engine",
    "Language", "File", "Line", "Function", "Snippet", "Reason",
    "Recommendation", "Confidence", "Tainted", "CWE", "OWASP", "Evidence IDs",
]


@register_reporter
class CSVReporter:
    name = "csv"
    file_extension = ".csv"

    def render(self, report_dict: dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(COLUMNS)

        # visible_findings() drops the not-yet-implemented Quantum
        # Readiness "Quantum Migration Inventory" inventory rows -- see
        # guardian/reporting/_shared.py.
        for f in visible_findings(report_dict):
            writer.writerow([
                # was f.get("id") — the model field is finding_id, so this
                # column was silently empty in every exported report.
                f.get("finding_id", ""),
                f.get("rule_id", ""),
                f.get("category", ""),
                f.get("severity", ""),
                f.get("source", "DETERMINISTIC"),
                f.get("engine", ""),
                f.get("language", ""),
                f.get("file", ""),
                f.get("line", 0),
                f.get("function", ""),
                str(f.get("snippet", "")).replace("\n", " ")[:150],
                str(f.get("reason", "")).replace("\n", " ")[:300],
                str(f.get("recommendation", "")).replace("\n", " "),
                f.get("confidence", 0.0),
                f.get("tainted", False),
                f.get("cwe") or "",
                f.get("owasp") or "",
                ";".join(f.get("evidence_ids", []) or []),
            ])

        return output.getvalue()
