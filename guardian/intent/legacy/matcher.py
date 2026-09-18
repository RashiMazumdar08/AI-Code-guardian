"""
Business Intent Engine — Matcher (v4 Enhanced)
================================================
Changes from v3:
- Evidence strings are now plain-English (no raw token sets)
- Company security policy (Company_Security_Policy.md) is loaded and cross-checked
- Each rule-type checker returns the *specific* code construct found or missing
- DirectoryMatcher caps files at MAX_FILES_PER_SCAN to stay fast on large repos
"""
from __future__ import annotations

import ast
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleMatch, RuleType

MAX_FILES_PER_SCAN = 500    # safety cap for large repos

# ─── Pattern catalogs ────────────────────────────────────────────────────────

_ROLE_CHECK = re.compile(
    r"\b(?:hasRole|isAdmin|isManager|checkPermission|authorize|"
    r"getAuthorities|isAuthenticated|@PreAuthorize|@Secured|"
    r"requiresRole|withRole|hasAuthority|SecurityContext|"
    r"principal\.role|user\.role|userRole|checkRole|"
    r"RoleCheck|AccessControl|isAuthorized)\b", re.I)

_AUTH_BYPASS = re.compile(
    r"\breturn\s+true\b|\bskipAuth\b|\bnoAuth\b|\bdisableAuth\b|"
    r"\bpermitAll\b|\.permitAll\(\)|UNSECURED|trustAllCerts|"
    r"setVerifier\(\s*(?:new\s+)?(?:Allow|Null)", re.I)

_VALIDATION = re.compile(
    r"\b(?:validate|isValid|Validator|@Valid|@NotNull|@Min|@Max|"
    r"@Size|@Pattern|@NotBlank|@Email|@Positive|@Range|"
    r"Objects\.requireNonNull|checkArgument|Assert\.|Preconditions\.|"
    r"if\s*\(.*==\s*null|if\s*\(.*\.isEmpty\(\)|StringUtils\.isEmpty|"
    r"StringUtils\.isBlank|validateInput|validateAmount|validateRequest)\b", re.I)

_NUMERIC_GUARD = re.compile(
    r"(?:>=|<=|>|<|==|!=)\s*(?:[\d_,]+|[A-Z_]+_LIMIT|[A-Z_]+_THRESHOLD|"
    r"[A-Z_]+_MAX|[A-Z_]+_MIN|MAX_AMOUNT|MIN_AMOUNT)", re.I)

_AUDIT_LOG = re.compile(
    r"\b(?:log\.|logger\.|Logger|auditLog|audit_log|logEvent|"
    r"writeAudit|AuditService|@Audited|publishEvent|eventBus|"
    r"AuditRepository|auditRepository|saveAuditEntry|logAccess|"
    r"AuditRecord|auditTrail|AUDIT)\b", re.I)

_WORKFLOW_GUARD = re.compile(
    r"\b(?:status\s*==|state\s*==|getStatus|getState|checkStatus|"
    r"APPROVED|PENDING|REJECTED|SUBMITTED|IN_REVIEW|ESCALATED|"
    r"StatusCheck|WorkflowService|transitionTo|moveToState)\b", re.I)

_RATE_LIMIT = re.compile(
    r"\b(?:RateLimiter|throttle|@RateLimited|rateLimitService|"
    r"requestsPerMinute|maxRequests|quotaExceeded|TooManyRequests|"
    r"RATE_LIMIT|rateLimitCheck)\b", re.I)


def _source_tokens(source: str) -> set[str]:
    raw = set(re.findall(r"[a-zA-Z][a-z]+|[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]+", source))
    raw |= set(re.findall(r"\b\w+\b", source.lower()))
    return {t.lower() for t in raw}


# ─── Per-rule-type checkers ──────────────────────────────────────────────────

def _check_authorization(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    if _AUTH_BYPASS.search(source):
        m = _AUTH_BYPASS.search(source)
        return (
            MatchStatus.VIOLATED, 0.92,
            f"Auth bypass found: '{m.group(0).strip()}'. Any user can perform this action."
        )
    m = _ROLE_CHECK.search(source)
    if m:
        return (
            MatchStatus.MATCHED, 0.88,
            f"Role/permission check found: '{m.group(0).strip()}'."
        )
    actor_present = rule.actor.lower() in source.lower()
    if actor_present:
        return (
            MatchStatus.PARTIAL, 0.52,
            f"The word '{rule.actor}' appears in the code but no access-control "
            f"guard (hasRole, @PreAuthorize, etc.) was found."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 0.82,
        f"No role check and no reference to '{rule.actor}' in this file."
    )


def _check_validation(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    m_val = _VALIDATION.search(source)
    m_num = _NUMERIC_GUARD.search(source)
    if m_val and m_num:
        return (
            MatchStatus.MATCHED, 0.88,
            f"Validation annotation/call '{m_val.group(0).strip()}' and numeric "
            f"guard '{m_num.group(0).strip()}' both found."
        )
    if m_val:
        return (
            MatchStatus.MATCHED, 0.78,
            f"Input validation found: '{m_val.group(0).strip()}'."
        )
    if m_num:
        return (
            MatchStatus.PARTIAL, 0.60,
            f"Numeric boundary check found ('{m_num.group(0).strip()}') but no "
            f"formal validation annotation (@Valid, @Min, etc.)."
        )
    action_words = set(rule.action.lower().split())
    src_tokens   = _source_tokens(source)
    if action_words & src_tokens:
        return (
            MatchStatus.PARTIAL, 0.42,
            f"The action '{rule.action}' is referenced in code but no validation "
            f"guard (@Valid, Objects.requireNonNull, etc.) was found."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 0.78,
        f"No validation logic found for '{rule.action}'."
    )


def _check_audit(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    m = _AUDIT_LOG.search(source)
    if m:
        return (
            MatchStatus.MATCHED, 0.87,
            f"Audit/logging call found: '{m.group(0).strip()}'."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 0.82,
        f"No audit logging pattern found for '{rule.action}'. "
        f"Expected: log.info(), auditLog.record(), @Audited, etc."
    )


def _check_workflow(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    m = _WORKFLOW_GUARD.search(source)
    if m:
        return (
            MatchStatus.MATCHED, 0.80,
            f"Workflow status check found: '{m.group(0).strip()}'."
        )
    action_words = set(rule.action.lower().split())
    if action_words & _source_tokens(source):
        return (
            MatchStatus.PARTIAL, 0.48,
            f"Action '{rule.action}' is referenced but no state/status guard was found. "
            f"The workflow step may execute regardless of current state."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 0.75,
        f"Workflow step '{rule.action}' not found in this file."
    )


def _check_rate_limit(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    m = _RATE_LIMIT.search(source)
    if m:
        return (
            MatchStatus.MATCHED, 0.83,
            f"Rate limiting mechanism found: '{m.group(0).strip()}'."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 0.76,
        f"No rate-limiting code found for '{rule.action}'. "
        f"Expected: RateLimiter, @RateLimited, or requestsPerMinute check."
    )


def _check_general(rule: BusinessRule, source: str) -> tuple[MatchStatus, float, str]:
    action_tokens = set(rule.action.lower().split())
    src_tokens    = _source_tokens(source)
    matched_words = action_tokens & src_tokens
    missing_words = action_tokens - src_tokens
    ratio = len(matched_words) / max(len(action_tokens), 1)

    if ratio >= 0.65:
        return (
            MatchStatus.MATCHED, ratio,
            f"Code contains the key terms for this rule: "
            f"{', '.join(sorted(matched_words)[:5])}."
        )
    if ratio >= 0.30:
        return (
            MatchStatus.PARTIAL, ratio,
            f"Partial match. Found: {', '.join(sorted(matched_words)[:3])}. "
            f"Missing: {', '.join(sorted(missing_words)[:3])}."
        )
    return (
        MatchStatus.NOT_IMPLEMENTED, 1 - ratio,
        f"Key terms for this rule not found in the code. "
        f"Expected: {', '.join(sorted(action_tokens)[:5])}."
    )


_CHECKER_MAP = {
    RuleType.AUTHORIZATION:  _check_authorization,
    RuleType.VALIDATION:     _check_validation,
    RuleType.AUDIT:          _check_audit,
    RuleType.WORKFLOW:       _check_workflow,
    RuleType.DATA_CONSTRAINT:_check_validation,
    RuleType.API_CONTRACT:   _check_general,
    RuleType.RATE_LIMIT:     _check_rate_limit,
    RuleType.GENERAL:        _check_general,
}


# ─── Base interface ──────────────────────────────────────────────────────────

class BaseMatcher(ABC):
    @abstractmethod
    def match(self, rule: BusinessRule, artefact_path: str, source: str) -> RuleMatch: ...

    def match_all(self, rules: list[BusinessRule], artefact_path: str, source: str) -> list[RuleMatch]:
        return [self.match(r, artefact_path, source) for r in rules]


# ─── Keyword matcher ─────────────────────────────────────────────────────────

class KeywordMatcher(BaseMatcher):

    def __init__(self, policy_text: str = ""):
        """
        policy_text: contents of Company_Security_Policy.md (optional).
        When provided, rules that contradict the policy are flagged VIOLATED.
        """
        self._policy = policy_text.lower()

    def match(self, rule: BusinessRule, artefact_path: str, source: str) -> RuleMatch:
        checker = _CHECKER_MAP.get(rule.rule_type, _check_general)
        status, confidence, evidence = checker(rule, source)

        # Policy cross-check: if policy mandates something and code bypasses it
        if self._policy and status != MatchStatus.VIOLATED:
            policy_keywords = {"no hardcoded secrets": _check_authorization,
                               "parameterized sql":    None,
                               "mfa required":         None,
                               "aes-256":              None}
            for kw in policy_keywords:
                if kw in self._policy and _AUTH_BYPASS.search(source):
                    status    = MatchStatus.VIOLATED
                    evidence += f" (Also violates company policy: '{kw}')"
                    confidence = max(confidence, 0.88)
                    break

        return RuleMatch(
            rule=rule,
            matched_artefact=artefact_path,
            status=status,
            confidence=confidence,
            evidence=evidence,
        )


# ─── Directory scanner ───────────────────────────────────────────────────────

class DirectoryMatcher:
    """Scans an entire source directory; returns best match per rule."""

    def __init__(self, matcher: Optional[BaseMatcher] = None,
                 policy_path: Optional[Path] = None):
        policy_text = ""
        if policy_path and policy_path.exists():
            try:
                policy_text = policy_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
        self._matcher = matcher or KeywordMatcher(policy_text)

    def match_against_directory(
        self,
        rules: list[BusinessRule],
        directory: Path,
        extensions: tuple[str, ...] = (".java", ".py"),
        exclude_dirs: tuple[str, ...] = ("test", "tests", ".git", "node_modules"),
    ) -> list[RuleMatch]:

        source_files: list[Path] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fn in files:
                if Path(fn).suffix in extensions:
                    source_files.append(Path(root) / fn)
            if len(source_files) >= MAX_FILES_PER_SCAN:
                break

        best: dict[str, RuleMatch] = {}
        for fp in source_files:
            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            try:
                rel = str(fp.relative_to(directory))
            except ValueError:
                rel = str(fp)
            for rule in rules:
                m = self._matcher.match(rule, rel, source)
                ex = best.get(rule.rule_id)
                if ex is None or m.confidence > ex.confidence:
                    best[rule.rule_id] = m

        result = []
        for rule in rules:
            if rule.rule_id in best:
                result.append(best[rule.rule_id])
            else:
                result.append(RuleMatch(
                    rule=rule,
                    matched_artefact="<no file scanned>",
                    status=MatchStatus.NOT_IMPLEMENTED,
                    confidence=1.0,
                    evidence="No source file in the scanned directory matched this rule.",
                ))
        return result
