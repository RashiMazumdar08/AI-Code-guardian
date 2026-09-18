"""
Rust language plugin — starter pattern set for security-relevant Rust
idioms. Patterns are tuned for backend/service code (actix/axum/reqwest/
diesel/sqlx ecosystems).

TODO(plugin-roadmap): Tree-sitter Rust AST rules; taint tracking through
format!/push_str chains; sqlx compile-time-checked-query awareness to
suppress FPs on `sqlx::query!` macros (which ARE parameterised).
"""
from __future__ import annotations

import re

from guardian.core.models import Finding
from guardian.core.registry import register_language
from guardian.scanner.common.secrets import entropy_gate

# (category, severity, rule_id, pattern, recommendation)
_PATTERNS = [
    ("SQL Injection", "High", "RS-SQLI-001",
     re.compile(r'(?i)format!\s*\(\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\{'),
     "Never build SQL with format!; use parameterised queries (sqlx query!/bind, diesel DSL)."),
    ("SQL Injection", "High", "RS-SQLI-002",
     re.compile(r'\.(execute|query|fetch_one|fetch_all|fetch_optional)\s*\(\s*&?format!'),
     "Query built via format! passed straight to a SQL executor; bind parameters instead."),
    ("Command Injection", "High", "RS-CMD-001",
     re.compile(r'Command::new\s*\([^)]*\)\s*(?:.|\n){0,80}?\.arg\s*\(\s*&?format!'),
     "Do not interpolate untrusted input into process arguments; validate/allowlist."),
    ("Broken Authentication", "Critical", "RS-TLS-001",
     re.compile(r'danger_accept_invalid_certs\s*\(\s*true\s*\)|danger_accept_invalid_hostnames\s*\(\s*true\s*\)'),
     "TLS certificate verification disabled; remove danger_accept_invalid_* in production paths."),
    ("Weak Crypto", "High", "RS-CRYPTO-001",
     re.compile(r'\b(md5|sha1)::\w|\bMd5::new\b|\bSha1::new\b|\buse\s+(md5|sha1)\b'),
     "MD5/SHA-1 are broken; use SHA-256+ (or SHA-3) and Argon2/bcrypt for passwords."),
    ("Insecure Deserialization", "Medium", "RS-DESER-001",
     re.compile(r'serde_(json|yaml)::from_(str|slice|reader)\s*::\s*<\s*serde_json::Value'),
     "Deserialising to untyped Value from untrusted input; prefer typed structs with validation."),
    ("Sensitive Logging", "High", "RS-LOG-001",
     re.compile(r'(?i)\b(?:println!|print!|dbg!|(?:log::)?(?:info|debug|warn|error|trace)!|tracing::(?:info|debug|warn|error|trace)!)\s*\([^)]*\b(password|secret|api_key|card_number|cvv|pan|ssn)\b'),
     "Sensitive values must never reach logs; redact or use masked/Secret types."),
    ("Insecure Random", "Medium", "RS-RAND-001",
     re.compile(r'(?i)\b(thread_rng|rand::random)\b[^;]{0,120}(token|secret|key|password|otp|nonce)'),
     "Use a CSPRNG (rand::rngs::OsRng / getrandom) for security-sensitive values."),
]

_SECRET = re.compile(
    r'(?i)\b(\w*(?:api_key|apikey|secret|token|password|passwd))\w*\s*[:=]\s*'
    r'(?:String::from\(|Some\()?\s*"([^"]{4,})"')

# Lines that are clearly test/example fixtures — suppress secret findings there.
_TEST_HINT = re.compile(r'(?i)#\[cfg\(test\)\]|mod\s+tests\b')


@register_language
class RustPlugin:
    name = "rust"
    extensions = (".rs",)

    def scan_source(self, source: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        in_test_module = bool(_TEST_HINT.search(source)) and "/tests/" in file_label.replace("\\", "/")
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            for category, severity, rule_id, pat, rec in _PATTERNS:
                if pat.search(line):
                    findings.append(Finding(
                        category=category, severity=severity, rule_id=rule_id,
                        file=file_label, line=lineno, snippet=stripped[:200],
                        recommendation=rec, confidence=0.6,
                    ))
                    break
            m = _SECRET.search(line)
            if m and not in_test_module and entropy_gate(m.group(1), m.group(2)):
                findings.append(Finding(
                    category="Hardcoded Secret", severity="High", rule_id="RS-SECRET-001",
                    file=file_label, line=lineno, snippet=stripped[:200],
                    recommendation="Load secrets from environment/vault, never string literals.",
                    confidence=0.7,
                ))
        return findings
