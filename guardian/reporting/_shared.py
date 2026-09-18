"""Shared helpers for the report formats (pdf/html/json/sarif/csv), so a
product decision -- "remove Quantum Readiness" or "the alignment score
must match the live Business Intent Engine result" -- is made once and
applied identically everywhere, instead of being reimplemented (and
drifting) separately in every reporter file.

Background: this app briefly had reporters disagreeing with each other
and with the live app on both of these numbers --

  * Quantum Readiness was never actually implemented, but its score tile,
    its own CBOM section, and "Quantum Migration Inventory" finding rows
    were still showing up in every exported report.
  * Business alignment is computed by TWO different engines:
    guardian.engines.business_intent (run inside the scan pipeline,
    stored as report["business_intent"] on the scan result -- and fed
    into report["unified_risk"]["alignment_score"] via
    guardian.core.unified_risk) defaults to a hardcoded 100% when nothing
    was judged; guardian.intent.engine (behind
    POST /api/business-intent/analyze) is what the frontend's Reports tab
    and Overview tile actually call live, and it scores that same case as
    0%. The frontend now always overrides report["business_intent"] with
    the live analyze-endpoint result before asking for a report, so that
    field is trustworthy -- but unified_risk.alignment_score is NOT
    automatically kept in sync with it, hence this helper.

See guardian/reporting/pdf_reporter.py for where this was first fixed.
"""
from __future__ import annotations

import re

# Categories belonging to the not-yet-implemented Quantum Readiness
# feature. guardian/core/unified_risk.py already excludes these from
# scoring (NON_SCORING_CATEGORIES); reporters must also exclude them from
# rendered findings tables, or "removed" quantum data just reappears as
# ordinary-looking rows in the findings list.
QUANTUM_CATEGORIES = {"Quantum Migration Inventory", "Quantum Readiness"}

# Secret-finding matching, aligned with the same strict category/rule
# matching already used elsewhere (guardian/copilot/assistant.py's
# _SECRET_CATEGORIES / SEC-004 pattern) rather than a loose "secret" in
# category substring check.
_SECRET_CATEGORIES = {"hardcoded secret", "hardcoded_secret", "secret", "exposed secret"}
# A quoted string literal of 3+ chars, e.g. the "hunter2" in
# DB_PASSWORD = "hunter2" or API_KEY: 'sk-abc123...'.
_QUOTED_VALUE_RE = re.compile(r'''(["'])((?:(?!\1).){3,})\1''')


def _is_secret_finding(finding: dict) -> bool:
    category = str(finding.get("category") or "").lower()
    rule = str(finding.get("rule_id") or finding.get("rule") or "").upper()
    return category in _SECRET_CATEGORIES or rule.startswith("SEC-004")


def redact_snippet(finding: dict) -> str:
    """The finding's code snippet, with quoted secret VALUES masked to
    asterisks for Hardcoded Secret findings (e.g. API_KEY = "sk-****...").
    Every other finding's snippet is returned unchanged -- this only ever
    masks the literal value the scanner itself already flagged as an
    exposed credential, never ordinary code content. Reports must never
    expose the actual secret they are warning about."""
    snippet = str(finding.get("snippet") or "")
    if not snippet or not _is_secret_finding(finding):
        return snippet

    def _mask(m: "re.Match[str]") -> str:
        quote, value = m.group(1), m.group(2)
        return f"{quote}{'*' * len(value)}{quote}"

    return _QUOTED_VALUE_RE.sub(_mask, snippet)


def visible_findings(report: dict) -> list[dict]:
    """scan.findings with quantum-inventory rows dropped and any Hardcoded
    Secret finding's snippet redacted. Every reporter (html/pdf/csv/sarif,
    and json via normalize_for_display -> strip_quantum) sources its
    finding list from here, so this is the single place secret redaction
    has to be applied to cover all five export formats at once."""
    findings = (report.get("scan") or {}).get("findings", []) or []
    out = []
    for f in findings:
        if f.get("category") in QUANTUM_CATEGORIES:
            continue
        if _is_secret_finding(f) and f.get("snippet"):
            f = {**f, "snippet": redact_snippet(f)}
        out.append(f)
    return out


def alignment_value(report: dict) -> float:
    """The one alignment percentage every report format should display."""
    bi = report.get("business_intent") or {}
    value = bi.get("alignment_percentage")
    if value is None:
        value = bi.get("alignment_score")
    if isinstance(value, (int, float)):
        return float(value)
    risk = report.get("unified_risk") or report.get("risk") or {}
    return float(risk.get("alignment_score", 0) or 0)


def _risk_key(report: dict) -> str | None:
    if "unified_risk" in report:
        return "unified_risk"
    if "risk" in report:
        return "risk"
    return None


def strip_quantum(report: dict) -> dict:
    """Shallow-copied report with the not-yet-implemented Quantum
    Readiness dimension removed: the "quantum" CBOM block, its score and
    weight inside unified_risk.dimensions, and its finding rows."""
    out = dict(report)
    out.pop("quantum", None)

    scan = out.get("scan")
    if isinstance(scan, dict):
        scan = dict(scan)
        scan["findings"] = visible_findings(report)
        out["scan"] = scan

    key = _risk_key(out)
    if key:
        risk = dict(out[key] or {})
        risk.pop("quantum_readiness_score", None)
        dims = risk.get("dimensions")
        if isinstance(dims, dict):
            dims = dict(dims)
            dims.pop("quantum_readiness", None)
            dims.pop("quantum", None)
            dims.pop("quantum_inventory_findings", None)
            weights = dims.get("weights")
            if isinstance(weights, dict):
                weights = dict(weights)
                weights.pop("quantum", None)
                weights.pop("quantum_readiness", None)
                dims["weights"] = weights
            risk["dimensions"] = dims
        out[key] = risk

    return out


def normalize_for_display(report: dict) -> dict:
    """strip_quantum() plus overwriting alignment_score, so a raw/machine
    export (JSON) matches what every other report format now displays."""
    out = strip_quantum(report)
    key = _risk_key(out)
    if key:
        risk = dict(out[key] or {})
        risk["alignment_score"] = alignment_value(report)
        out[key] = risk
    return out
