"""Query-aware, evidence-grounded Copilot response synthesis."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple


SMALL_TALK = {
    "hi", "hii", "hiii", "hello", "hey", "heyy", "ok", "okay", "cool",
    "thanks", "thank you", "yo", "good morning", "good afternoon", "good evening",
}

STOPWORDS = {
    "a", "an", "and", "are", "as", "be", "been", "by", "do", "does", "done",
    "for", "from", "how", "i", "in", "is", "it", "me", "of", "on", "or", "so",
    "tell", "that", "the", "then", "there", "this", "to", "was", "what", "when",
    "where", "why", "with", "should", "can", "could", "would", "please", "about",
}

REMEDIATION_TERMS = {
    "fix", "fixed", "remediate", "remediation", "solve", "solution", "solutions",
    "done", "patch", "prevent", "mitigate", "change", "secure",
}

SUMMARY_TERMS = {"summary", "overview", "posture", "risk", "risks", "findings", "vulnerabilities"}

RULE_HINTS = {
    "SEC-001": ("SQL Injection", "Use parameterized queries and avoid string-built SQL."),
    "SEC-002": ("Cross-Site Scripting", "Use context-aware output encoding and avoid unsafe HTML sinks."),
    "SEC-004": ("Hardcoded Secret", "Move secrets and sensitive paths into environment-backed configuration or a secret manager."),
    "SEC-006": ("Broken Authentication", "Keep TLS/certificate verification enabled and avoid auth bypass patterns."),
    "SEC-010": ("Sensitive Logging", "Remove or mask sensitive values before logging."),
}


_EXT_LANGUAGE = {
    ".py": "python", ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rs": "rust",
}


def _infer_language_from_path(file_path: str) -> str:
    """Best-effort language guess from a file extension, used when a
    finding dict doesn't carry an explicit `language` field."""
    for ext, lang in _EXT_LANGUAGE.items():
        if file_path.lower().endswith(ext):
            return lang
    return "python"


def synthesize_security_answer(
    user_query: str,
    findings: Iterable[Any],
    *,
    evidence: Optional[Iterable[Dict[str, Any]]] = None,
    profile: Optional[Dict[str, Any]] = None,
    risk_scores: Optional[Dict[str, Any]] = None,
    persona: str = "Developer",
    conversation: Optional[Iterable[Any]] = None,
    knowledge: Optional[Iterable[Dict[str, Any]]] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Return a grounded answer and compact citations for a user question."""
    query = (user_query or "").strip()
    query_lower = query.lower()
    normalized_findings = [_normalize_finding(f) for f in findings]

    if _is_small_talk(query_lower):
        repo = (profile or {}).get("repo_path") or (profile or {}).get("root") or "the active repository"
        return (
            f"Hi. I am your AI Security Copilot for {repo}.\n\n"
            "Ask me about a finding, a file, a rule such as `SEC-004`, or say "
            "`what should be fixed first` and I will ground the answer in the current scan.",
            [],
        )

    if not normalized_findings:
        return (
            "I do not see any active scan findings loaded for this conversation yet. "
            "Run a repository scan first, then ask about a rule, file, category, or remediation.",
            [],
        )

    query_scope = _conversation_scope(query, conversation)
    matched = _rank_findings(query_scope, normalized_findings)

    wants_summary = any(term in query_lower for term in SUMMARY_TERMS)
    wants_fix = any(term in query_lower for term in REMEDIATION_TERMS) or _is_vague_followup(query_lower)

    if wants_summary and not wants_fix and not _specific_terms(query):
        return _summary_answer(normalized_findings, profile or {}, risk_scores or {})

    if not matched and _is_vague_followup(query_lower):
        matched = _top_priority_findings(normalized_findings)

    if not matched:
        rules = ", ".join(f"`{r}`" for r in sorted({f["rule_id"] for f in normalized_findings if f["rule_id"]})[:8])
        return (
            f"I do not see evidence for that specific issue in the current scan.\n\n"
            f"Current scan rules I can discuss include: {rules or 'no rule IDs available'}. "
            "Try asking about a rule ID, file path, category, or `what should be fixed first`.",
            [],
        )

    finding = matched[0]
    citations = [_citation(f) for f in matched[:4]]
    answer = _finding_answer(finding, matched, wants_fix=wants_fix, persona=persona, knowledge=list(knowledge or []))
    return answer, citations


def _is_small_talk(query_lower: str) -> bool:
    return query_lower in SMALL_TALK or bool(re.fullmatch(r"(hi+|hello+|hey+|ok+|thanks?)[.! ]*", query_lower))


def _normalize_finding(finding: Any) -> Dict[str, Any]:
    if hasattr(finding, "to_dict"):
        raw = finding.to_dict()
    elif isinstance(finding, dict):
        raw = dict(finding)
    else:
        raw = {}

    evidence_ids = raw.get("evidence_ids") or []
    if isinstance(evidence_ids, str):
        evidence_ids = [evidence_ids]
    evidence_id = raw.get("evidence_id") or (evidence_ids[0] if evidence_ids else "")

    return {
        "finding_id": raw.get("finding_id") or raw.get("id") or "",
        "rule_id": raw.get("rule_id") or raw.get("rule") or "",
        "category": raw.get("category") or raw.get("title") or "Security Finding",
        "severity": str(raw.get("severity") or "Medium"),
        "file_path": raw.get("file_path") or raw.get("file") or "unknown",
        "line_number": raw.get("line_number") or raw.get("line") or 0,
        "description": raw.get("description") or raw.get("reason") or raw.get("recommendation") or "",
        "snippet": raw.get("snippet") or raw.get("code_snippet") or "",
        "recommendation": raw.get("recommendation") or "",
        "evidence_id": evidence_id,
        "confidence": raw.get("confidence", 0.0),
        "is_exploitable": bool(raw.get("is_exploitable", False)),
        # Preserve the finding's actual source language so remediation
        # suggestions can be language-appropriate instead of defaulting
        # to Python for every finding (see _code_fix_for).
        "language": (raw.get("language") or _infer_language_from_path(
            raw.get("file_path") or raw.get("file") or "")),
    }


def _conversation_scope(query: str, conversation: Optional[Iterable[Any]]) -> str:
    parts = []
    for msg in list(conversation or [])[-6:]:
        if isinstance(msg, dict):
            parts.append(str(msg.get("content", "")))
        else:
            parts.append(str(getattr(msg, "content", "")))
    parts.append(query)
    return "\n".join(p for p in parts if p).strip()


def _tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9_.:/-]+", text.lower()) if len(t) > 2 and t not in STOPWORDS]


def _specific_terms(query: str) -> List[str]:
    return [t for t in _tokens(query) if t not in REMEDIATION_TERMS and t not in SUMMARY_TERMS]


def _rank_findings(query: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tokens = _tokens(query)
    if not tokens:
        return []

    scored: List[Tuple[int, Dict[str, Any]]] = []
    for f in findings:
        haystack = " ".join(
            str(f.get(k, ""))
            for k in ("finding_id", "rule_id", "category", "file_path", "description", "snippet", "recommendation")
        ).lower()
        score = 0
        for token in tokens:
            if token and token in haystack:
                score += 3 if token.startswith("sec-") or token in str(f.get("rule_id", "")).lower() else 1
        if score:
            score += _severity_weight(f.get("severity", ""))
            if f.get("is_exploitable"):
                score += 2
            scored.append((score, f))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [f for _, f in scored]


def _top_priority_findings(findings: List[Dict[str, Any]], limit: int = 4) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (_severity_weight(f.get("severity", "")), bool(f.get("is_exploitable")), f.get("confidence", 0.0)),
        reverse=True,
    )[:limit]


def _severity_weight(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(str(severity).lower(), 0)


def _is_vague_followup(query_lower: str) -> bool:
    return any(phrase in query_lower for phrase in [
        "what should be done", "what to do", "what now", "how to fix", "fix this",
        "solution", "solutions", "remediate", "remediation", "what should i do",
    ])


def _summary_answer(findings: List[Dict[str, Any]], profile: Dict[str, Any], risk_scores: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    severity_counts = Counter(f["severity"] for f in findings)
    category_counts = Counter(f["category"] for f in findings)
    top = _top_priority_findings(findings, limit=5)
    lines = [
        "**Context:** The current scan has "
        f"{len(findings)} security finding(s) for `{profile.get('repo_path') or profile.get('root') or 'the active repository'}`.",
        "",
        "**The Risk:** The highest-volume categories are "
        + ", ".join(f"{cat} ({count})" for cat, count in category_counts.most_common(4))
        + f". Severity distribution: {dict(severity_counts)}.",
        "",
        "**Remediation:** Start with these highest-priority items:",
    ]
    for idx, f in enumerate(top, 1):
        lines.append(f"{idx}. `{f['rule_id'] or f['category']}` in `{f['file_path']}:{f['line_number']}` - {_remediation_for(f)}")
    if risk_scores:
        lines.append(f"\nCurrent composite risk: `{risk_scores.get('composite_risk_score', 0.0)}`.")
    return "\n".join(lines), [_citation(f) for f in top]


def _finding_answer(
    finding: Dict[str, Any],
    matched: List[Dict[str, Any]],
    *,
    wants_fix: bool,
    persona: str,
    knowledge: List[Dict[str, Any]],
) -> str:
    rule = finding["rule_id"] or finding["category"]
    location = f"`{finding['file_path']}:{finding['line_number']}`"
    category = finding["category"]
    snippet = finding["snippet"].strip()

    lines = [
        f"**Context:** `{rule}` was found in {location}. It is categorized as **{category}**"
        f" with **{finding['severity']}** severity.",
    ]
    if finding["description"]:
        lines.append(f"The scanner reason is: {finding['description']}")

    lines.extend([
        "",
        f"**The Risk:** {_risk_for(finding)}",
        "",
        f"**Remediation:** {_remediation_for(finding)}",
    ])

    code = _code_fix_for(finding)
    if code:
        fence_lang = {
            "javascript": "javascript", "typescript": "typescript",
            "java": "java", "rust": "rust", "python": "python",
        }.get(str(finding.get("language") or "python").lower(), "text")
        lines.append("\nSuggested pattern:")
        lines.append(f"```{fence_lang}\n{code}\n```")

    if snippet and not wants_fix:
        lines.append("\nRelevant snippet:")
        lines.append(f"```text\n{snippet[:400]}\n```")

    if len(matched) > 1:
        lines.append(f"\nI found {len(matched)} related finding(s). The next closest matches are:")
        for f in matched[1:4]:
            lines.append(f"- `{f['rule_id'] or f['category']}` in `{f['file_path']}:{f['line_number']}`")

    if knowledge:
        top = knowledge[0]
        title = top.get("title") or top.get("standard") or "security guidance"
        lines.append(f"\nRelated guidance: {title}.")

    return "\n".join(lines)


# Exact rule-id / category matches only — substring checks like `"sql" in category`
# used to misfire on unrelated categories that merely contain the substring
# (e.g. a category named "Insecure SQL Logging" would match both "sql" and
# "logging" branches). Rule IDs are matched by prefix (SEC-001, SEC-001-B, ...)
# and categories by an exact set of known spellings.
_SQLI_CATEGORIES = {"sql injection", "sql_injection", "sqli"}
_SECRET_CATEGORIES = {"hardcoded secret", "hardcoded_secret", "secret", "exposed secret"}
_XSS_CATEGORIES = {"cross-site scripting", "xss", "cross site scripting"}
_AUTH_CATEGORIES = {"broken authentication", "broken_authentication", "authentication bypass"}
_LOGGING_CATEGORIES = {"sensitive logging", "sensitive_logging", "insecure logging"}


def _matches(category: str, rule: str, categories: set, rule_prefix: str) -> bool:
    return category in categories or rule.startswith(rule_prefix)


def _risk_for(finding: Dict[str, Any]) -> str:
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    if _matches(category, rule, _SQLI_CATEGORIES, "SEC-001"):
        return "SQL injection can let attacker-controlled input change database queries, leading to data exposure or unauthorized changes."
    if _matches(category, rule, _SECRET_CATEGORIES, "SEC-004"):
        return "Hardcoded secrets or sensitive token paths can expose credentials, make rotation difficult, and leak environment assumptions into source control."
    if _matches(category, rule, _XSS_CATEGORIES, "SEC-002"):
        return "Cross-site scripting can allow attacker-controlled content to execute in a user's browser."
    if _matches(category, rule, _AUTH_CATEGORIES, "SEC-006"):
        return "Authentication or TLS verification weaknesses can allow bypass, impersonation, or man-in-the-middle exposure."
    if _matches(category, rule, _LOGGING_CATEGORIES, "SEC-010"):
        return "Sensitive logging can place credentials or private data into logs where retention and access controls are weaker."
    return "This finding can weaken the application's security posture if the affected code is reachable or handles sensitive data."


def _remediation_for(finding: Dict[str, Any]) -> str:
    rec = finding.get("recommendation", "").strip()
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    if rec and "parameterized coding standards" not in rec.lower():
        return rec
    if _matches(category, rule, _SQLI_CATEGORIES, "SEC-001"):
        return "Replace string-built SQL with parameterized queries, validate inputs, and keep query structure static."
    if _matches(category, rule, _SECRET_CATEGORIES, "SEC-004"):
        return "Move the value into environment-backed configuration or a secret manager, restrict runtime file permissions, rotate any exposed token, and keep token files out of source control."
    if _matches(category, rule, _XSS_CATEGORIES, "SEC-002"):
        return "Use context-aware escaping, avoid unsafe HTML sinks, and sanitize user-controlled content before rendering."
    if _matches(category, rule, _AUTH_CATEGORIES, "SEC-006"):
        return "Remove bypass patterns, keep certificate verification enabled, and add regression tests for the auth/TLS path."
    if _matches(category, rule, _LOGGING_CATEGORIES, "SEC-010"):
        return "Remove sensitive fields from logs or mask them before logging."
    return rec or "Apply the scanner recommendation, add a regression test, and rerun the scan to confirm the finding is gone."


def _code_fix_for(finding: Dict[str, Any]) -> str:
    """Return a fix suggestion appropriate to the finding's actual language.

    Previously this always returned Python code (`import os`,
    `cursor.execute(...)`) regardless of whether the finding was in Java,
    JavaScript, TypeScript, or Rust — a visible hallucination. Suggestions
    are now language-aware, and fall back to the scanner's own
    recommendation when the language isn't one we have a canned pattern
    for, rather than guessing Python.
    """
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    language = str(finding.get("language") or "python").lower()
    snippet = finding["snippet"]

    if _matches(category, rule, _SECRET_CATEGORIES, "SEC-004"):
        var_match = re.search(r"\b([A-Z][A-Z0-9_]{2,})\s*=", snippet)
        var_name = var_match.group(1) if var_match else "SECRET_VALUE"
        if language == "python":
            return f"import os\n\n{var_name} = os.environ.get(\"{var_name}\", \"\")"
        if language == "java":
            return f"// Use environment variable or Spring @Value\nString {var_name} = System.getenv(\"{var_name}\");"
        if language in ("javascript", "typescript"):
            return f"const {var_name} = process.env.{var_name} || '';"
        if language == "rust":
            return f"let {var_name} = std::env::var(\"{var_name}\").unwrap_or_default();"
        return finding.get("recommendation") or "Use environment variables instead of hardcoded secrets."

    if _matches(category, rule, _SQLI_CATEGORIES, "SEC-001"):
        if language == "python":
            return "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        if language == "java":
            return "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setInt(1, userId);"
        if language in ("javascript", "typescript"):
            return "db.query(\"SELECT * FROM users WHERE id = $1\", [userId]);"
        if language == "rust":
            return "sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id).fetch_one(&pool).await?;"
        return finding.get("recommendation") or "Use parameterized queries to prevent SQL injection."

    if _matches(category, rule, _XSS_CATEGORIES, "SEC-002"):
        if language == "python":
            return "import html\n\nsafe_output = html.escape(user_input)"
        if language == "java":
            return "String safeOutput = org.owasp.encoder.Encode.forHtml(userInput);"
        if language in ("javascript", "typescript"):
            return "const safeOutput = escapeHtml(userInput); // or a templating engine's auto-escaping"
        if language == "rust":
            return "let safe_output = askama_escape::escape(user_input, askama_escape::Html);"
        return finding.get("recommendation") or "Use context-aware output encoding before rendering untrusted input."

    return finding.get("recommendation") or ""


def _citation(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "evidence_id": finding.get("evidence_id", ""),
        "finding_id": finding.get("finding_id", ""),
        "file_path": finding.get("file_path", "unknown"),
        "line_number": finding.get("line_number", 0),
        "rule_id": finding.get("rule_id", ""),
        "confidence": finding.get("confidence", 0.0),
    }
