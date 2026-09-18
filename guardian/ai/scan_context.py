"""
AI Assistant — Scan Context Grounding
=====================================
Fixes hallucination cause #3: scan findings never reached the model, so
questions about findings — the platform's core use case — were answered
from imagination.

Two mechanisms:

1. `findings_to_documents(report)` — converts every Finding in a scan
   report into an indexable Document (doc_type SCAN_REPORT) so semantic
   retrieval can surface findings for fuzzy questions
   ("what's wrong with the payment code?").

2. `exact_match_context(question, report)` — deterministic lookup: if
   the question literally names a rule ID, finding ID, or file path
   that exists in the report, the exact finding records are injected
   verbatim into the prompt. Exact questions get exact context —
   retrieval similarity never gets the chance to miss.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

from guardian.ai.models import Document, DocumentType
from guardian.reporting import report_view_model as rvm

_TOKEN = re.compile(r"[\w./\-]{3,}")


def finding_text(f: dict) -> str:
    return (f"FINDING {f.get('finding_id', '?')} | rule {f.get('rule_id')} | "
            f"{f.get('severity')} {f.get('category')} | "
            f"{f.get('file')}:{f.get('line')}\n"
            f"code: {f.get('snippet', '')}\n"
            f"recommendation: {f.get('recommendation', '')}\n"
            f"cwe: {f.get('cwe') or 'n/a'} | owasp: {f.get('owasp') or 'n/a'} | "
            f"confidence: {f.get('confidence')}")


def findings_to_documents(report: dict) -> list[Document]:
    docs: list[Document] = []
    for f in report.get("scan", {}).get("findings", []):
        text = finding_text(f)
        docs.append(Document(
            doc_id=hashlib.sha256(text.encode()).hexdigest()[:16],
            content=text,
            source_path=str(f.get("file", "scan_report")),
            doc_type=DocumentType.SCAN_REPORT,
            start_line=int(f.get("line") or 0),
            end_line=int(f.get("line") or 0),
            metadata={"finding_id": f.get("finding_id"),
                      "rule_id": f.get("rule_id"),
                      "severity": f.get("severity")},
        ))
    # one summary document so "how did the scan go overall" is answerable
    risk = report.get("risk", {})
    scan = report.get("scan", {})
    # Repository Security Status: the same plain-English vocabulary the
    # HTML reports and Reports page use (guardian.reporting.
    # report_view_model.compute_verdict()) -- never the raw internal
    # merge_decision field, so the chatbot can never surface source-control
    # workflow language it was never asked to reason about.
    by_sev_lower = {str(k).lower(): v for k, v in (scan.get("by_severity", {}) or {}).items()}
    verdict = rvm.compute_verdict(
        True, scan.get("total_findings", 0) or 0,
        by_sev_lower.get("critical", 0) or 0, by_sev_lower.get("high", 0) or 0,
        {}, None,
    )
    summary_content = ("SCAN SUMMARY | target " + str(scan.get("target"))
                 + f" | files_scanned {scan.get('files_scanned')}"
                 + f" | total_findings {scan.get('total_findings')}"
                 + f" | by_severity {json.dumps(scan.get('by_severity', {}))}"
                 + f" | security_score {risk.get('security_score')}"
                 + f" | overall_risk {risk.get('overall_risk_score')}"
                 + f" | repository_security_status {verdict['label']}")
    docs.append(Document(
        doc_id=hashlib.sha256(summary_content.encode()).hexdigest()[:16],
        content=summary_content,
        source_path="scan:summary",
        doc_type=DocumentType.RISK_REPORT,
    ))
    return docs


def exact_match_context(question: str, report: Optional[dict],
                        max_findings: int = 6) -> str:
    """Deterministic context: findings whose rule_id, finding_id, or file
    path literally appears in the question, OR a structured findings summary
    if the user asks generally about repo findings / vulnerabilities."""
    if not report:
        return ""
    findings = report.get("scan", {}).get("findings", [])
    if not findings:
        return ""

    q_lower = question.lower()
    q_tokens = {t.lower() for t in _TOKEN.findall(question)}

    # Check for specific finding/rule/file hits first
    hits: list[dict] = []
    for f in findings:
        rid = str(f.get("rule_id") or "").lower()
        fid = str(f.get("finding_id") or "").lower()
        fpath = str(f.get("file") or "").lower().replace("\\", "/")
        fname = fpath.rsplit("/", 1)[-1]
        if (rid and rid in q_tokens) or (fid and fid in q_tokens) \
                or (fpath and fpath in q_lower) or (fname and fname in q_tokens):
            hits.append(f)
        if len(hits) >= max_findings:
            break

    if hits:
        body = "\n\n".join(finding_text(f) for f in hits)
        return ("EXACT SCAN-REPORT MATCHES for this question "
                "(authoritative — prefer these over any other context):\n" + body)

    # If no specific hit, check if user is asking generally about repo findings / vulnerabilities
    # Includes typo tolerance (e.g. 'finidings', 'vulns', 'bugs')
    is_general_findings_query = bool(re.search(
        r"\b(findings?|finidings?|vulnerabilit(y|ies)|vulns?|bugs?|issues?|scan|repo|audit|summary|overview)\b",
        q_lower
    ))

    if is_general_findings_query:
        summary_lines = []
        scan_info = report.get("scan", {})
        total = scan_info.get("total_findings", len(findings))
        by_sev = scan_info.get("by_severity", {})

        summary_lines.append(f"REPOSITORY FINDINGS SUMMARY:")
        summary_lines.append(f"- Total Detected Findings: {total}")
        summary_lines.append(f"- Severity Distribution: {json.dumps(by_sev)}")
        summary_lines.append(f"\nDETAILED FINDINGS EVIDENCE:")

        for idx, f in enumerate(findings[:10], 1):
            summary_lines.append(
                f"Finding #{idx}:\n"
                f"  - ID: {f.get('finding_id', f'SEC-{idx}')}\n"
                f"  - Severity: {f.get('severity', 'UNKNOWN')}\n"
                f"  - Rule ID: {f.get('rule_id', 'N/A')}\n"
                f"  - Category: {f.get('category', 'Security Finding')}\n"
                f"  - Location: {f.get('file', 'unknown')}:{f.get('line', 1)}\n"
                f"  - Code Snippet: {f.get('snippet', '').strip()}\n"
                f"  - Recommendation: {f.get('recommendation', 'Apply secure coding practices.')}\n"
                f"  - CWE / OWASP: {f.get('cwe', 'N/A')} / {f.get('owasp', 'N/A')}\n"
            )

        return "\n".join(summary_lines)

    return ""

