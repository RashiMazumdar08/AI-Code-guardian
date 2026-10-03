"""
Rate Limit & Error Sanitization Utility
=======================================
Parses LLM provider 429 rate limit / quota errors, extracts token metrics when reliable,
sanitizes internal implementation details (API keys, org IDs, model/provider names),
and generates clean, professional user-facing warning messages.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


def is_rate_limit_error(exc: Any) -> bool:
    """Detect 429 / rate limit / quota exhaustion condition reliably."""
    if exc is None:
        return False
    from guardian.llm.base import LLMRateLimitError
    if isinstance(exc, LLMRateLimitError):
        return True
    text = str(exc).lower()
    return any(
        kw in text
        for kw in (
            "429",
            "rate limit",
            "rate_limit",
            "rate_limit_exceeded",
            "quota",
            "tpd",
            "tpm",
            "resourceexhausted",
            "limit reached",
            "tokens per day",
            "tokens per minute",
        )
    ) or ("limit" in text and any(w in text for w in ("used", "requested", "exceeded", "reached", "tokens")))


def is_daily_quota_error(exc: Any) -> bool:
    """Detect if an exception or error message indicates provider daily token/request quota (TPD/RPD) exhaustion."""
    if exc is None:
        return False
    text = str(exc).lower()
    return any(
        kw in text
        for kw in (
            "tpd",
            "rpd",
            "tokens per day",
            "requests per day",
            "200000",
            "200,000",
            "daily quota",
            "daily limit",
            "day limit",
            "per day",
            "quota_exceeded",
            "resource_exhausted",
            "resourceexhausted",
            "provider_daily_quota",
            "generaterequestsperday",
            "free_tier_requests",
            "freetier",
        )
    )


def classify_llm_error(exc: Any) -> str:
    """
    Classify LLM errors into structured status categories:
    - SKIPPED_BUDGET: Per-scan local token admission budget reached
    - PROVIDER_DAILY_QUOTA: Provider daily token quota (TPD) exhausted
    - RATE_LIMITED: Provider per-minute rate limit (TPM)
    - PROVIDER_UNAVAILABLE: Connection, HTTP 5xx, or authentication errors
    """
    if exc is None:
        return "OK"
    text = str(exc)
    if "SKIPPED_BUDGET" in text:
        return "SKIPPED_BUDGET"
    if is_rate_limit_error(exc):
        if is_daily_quota_error(exc):
            return "PROVIDER_DAILY_QUOTA"
        return "RATE_LIMITED"
    return "PROVIDER_UNAVAILABLE"


def extract_token_metrics(error_text: str) -> Dict[str, Optional[int]]:
    """
    Extract token usage numbers from provider 429 error messages.
    Supports formats like:
      'Limit 200000, Used 199401, Requested 843'
      'limit: 200000, used: 199401, requested: 843'
    Computes 'remaining' as max(0, limit - used) if both limit and used are present.
    """
    metrics: Dict[str, Optional[int]] = {
        "limit": None,
        "used": None,
        "remaining": None,
        "requested": None,
    }
    if not error_text:
        return metrics

    # Extract limit
    m_limit = re.search(r"(?:limit|tpd|tpm)\s*[:=]?\s*(\d[\d,]*)", error_text, re.I)
    if m_limit:
        try:
            metrics["limit"] = int(m_limit.group(1).replace(",", ""))
        except ValueError:
            pass

    # Extract used
    m_used = re.search(r"(?:used)\s*[:=]?\s*(\d[\d,]*)", error_text, re.I)
    if m_used:
        try:
            metrics["used"] = int(m_used.group(1).replace(",", ""))
        except ValueError:
            pass

    # Extract requested
    m_req = re.search(r"(?:requested)\s*[:=]?\s*(\d[\d,]*)", error_text, re.I)
    if m_req:
        try:
            metrics["requested"] = int(m_req.group(1).replace(",", ""))
        except ValueError:
            pass

    # Compute remaining if limit and used are available
    if metrics["limit"] is not None and metrics["used"] is not None:
        metrics["remaining"] = max(0, metrics["limit"] - metrics["used"])

    return metrics


def sanitize_error_text(text: str) -> str:
    """
    Remove sensitive internal details:
    - Model/provider names (Nemotron, Groq, openai/gpt-oss-120b, nvidia/...)
    - API keys (gsk_..., xai-..., nvapi-...)
    - Org IDs / Request IDs (org_..., req_...)
    - Internal URLs (https://console.groq.com/..., etc.)
    - File paths / Stack traces
    """
    if not text:
        return ""

    # Redact credentials & tokens
    s = re.sub(r"\b(gsk_|xai-|nvapi-|sk-)[A-Za-z0-9_\-]+\b", "[REDACTED_KEY]", text)
    # Redact Org IDs & Request IDs
    s = re.sub(r"\b(org|req|req_id|job)_[A-Za-z0-9_\-]+\b", "[REDACTED_ID]", s, flags=re.I)
    # Redact URLs
    s = re.sub(r"https?://\S+", "", s)
    # Redact provider/model identifiers
    s = re.sub(r"\b(nemotron|groq|openai/gpt-oss-[A-Za-z0-9_\-]+|nvidia/[A-Za-z0-9_\-]+|grok-[A-Za-z0-9_\-]+)\b", "[AI Provider]", s, flags=re.I)
    return s.strip()


def extract_finding_context(
    user_query: str = "",
    scan_report: Optional[Dict[str, Any]] = None,
    state: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract the finding title and evidence details from user query or scan/state context.
    Never hardcodes finding names.
    """
    finding_title: Optional[str] = None
    evidence_str: Optional[str] = None

    # 1. Try extracting from user query (e.g., "Tell me more about finding: Hardcoded Secret")
    if user_query:
        m = re.search(r"finding:\s*(.+)", user_query, re.I)
        if m:
            finding_title = m.group(1).strip()

    # 2. Look up finding details in scan_report or state
    findings: List[Dict[str, Any]] = []
    if scan_report and isinstance(scan_report, dict):
        findings = scan_report.get("scan", {}).get("findings", []) or scan_report.get("findings", [])
    elif state and isinstance(state, dict):
        findings = state.get("findings", [])

    if findings:
        matched_finding = None
        if finding_title:
            for f in findings:
                f_name = str(f.get("rule_id") or f.get("title") or f.get("category") or "")
                if finding_title.lower() in f_name.lower() or f_name.lower() in finding_title.lower():
                    matched_finding = f
                    break
        if not matched_finding and len(findings) > 0:
            matched_finding = findings[0]
            if not finding_title:
                finding_title = matched_finding.get("rule_id") or matched_finding.get("title") or matched_finding.get("category")

        if matched_finding:
            file_path = matched_finding.get("file_path") or matched_finding.get("file") or "scan_report.json"
            line = matched_finding.get("line_number") or matched_finding.get("line")
            if line:
                evidence_str = f"{file_path} — line {line}"
            else:
                evidence_str = str(file_path)

    return finding_title, evidence_str


def format_rate_limit_warning(
    exc: Any,
    user_query: str = "",
    scan_report: Optional[Dict[str, Any]] = None,
    state: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build clean, professional 429 quota warning message without exposing internal details.
    """
    raw_text = str(exc)
    log.warning("LLM rate limit / quota condition encountered: %s", sanitize_error_text(raw_text))

    metrics = extract_token_metrics(raw_text)
    finding_title, evidence_str = extract_finding_context(user_query, scan_report, state)
    daily = is_daily_quota_error(raw_text)

    if daily:
        lines = [
            "⚠️ PROVIDER_DAILY_QUOTA: Daily token quota exhausted",
            "⚠️ AI explanation temporarily unavailable",
            "",
            "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic findings are fully preserved.",
        ]
    else:
        lines = [
            "⚠️ AI explanation temporarily unavailable",
            "",
            "The AI reasoning service has reached its current usage limit, so an AI explanation could not be generated right now.",
        ]

    # Include token usage information if provider gave reliable values
    usage_lines = []
    if metrics["used"] is not None and metrics["limit"] is not None:
        usage_lines.append(f"Usage: {metrics['used']:,} / {metrics['limit']:,} tokens")
    elif metrics["limit"] is not None:
        usage_lines.append(f"Limit: {metrics['limit']:,} tokens")

    if metrics["remaining"] is not None:
        usage_lines.append(f"Remaining: {metrics['remaining']:,} tokens")

    if metrics["requested"] is not None:
        usage_lines.append(f"Requested: ~{metrics['requested']:,} tokens")

    if usage_lines:
        lines.append("")
        lines.extend(usage_lines)

    lines.append("")
    lines.append("Your security finding and supporting evidence are still available.")

    if finding_title:
        lines.append("")
        lines.append(f"Finding: {finding_title}")
    if evidence_str:
        lines.append(f"Evidence: {evidence_str}")

    return "\n".join(lines)
