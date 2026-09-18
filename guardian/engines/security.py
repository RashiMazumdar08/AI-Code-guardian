"""
UST Security Engine
===================
Deterministic security analysis driven by the Unified Syntax Tree.

The flow is deliberately *not* `rule -> vulnerability`. It is:

    UST node  ->  rule match  ->  candidate Evidence  ->  contextual
                  checks (data-flow, arguments, scope)  ->  Finding

Two consequences matter:

  * every Finding this engine emits cites the Evidence IDs that justify
    it, so a report can explain itself and an AI layer can be held to
    the same standard;
  * a rule match alone is not a finding. `cursor.execute(q)` is evidence
    of a database operation; it becomes a SQL-injection finding only
    when the data-flow pass shows untrusted input reaching it through
    dynamic string construction.

The existing OWASP/CWE rule catalog (`data/rules/Security_Rules.json`) is
preserved and supplies severity, rule IDs and recommendations, so
existing report consumers see the same categories they always did.

Secret detection stays regex + Shannon entropy: syntax parsing gives no
advantage for "does this string literal look like a credential", and the
tuned entropy gate from v1 already works. It is applied to UST literal
nodes where available, falling back to a line scan.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

from guardian.core.context import AnalysisContext
from guardian.core.models import Finding, Severity
from guardian.engines.base import BaseEngine, EngineResult
from guardian.evidence.models import Evidence, EvidenceType
from guardian.scanner.common.secrets import entropy_gate
from guardian.ust.models import USTFile, USTNode, USTNodeType

log = logging.getLogger(__name__)

DEFAULT_RULES_PATH = (Path(__file__).resolve().parent.parent.parent
                      / "data" / "rules" / "Security_Rules.json")

ENGINE_NAME = "security"
DETECTOR = "ust_security_engine"


# ---------------------------------------------------------------------------
# Rule catalog
# ---------------------------------------------------------------------------
def load_rule_catalog(path: Path = DEFAULT_RULES_PATH) -> dict[str, dict]:
    try:
        with open(path) as fh:
            return {r["category"]: r for r in json.load(fh)}
    except (OSError, ValueError, KeyError) as exc:
        log.warning("could not load security rule catalog %s: %s", path, exc)
        return {}


#: sink kind (from UST security tags) -> (category, cwe, owasp, severity)
SINK_CATEGORIES: dict[str, tuple[str, str, str, str]] = {
    "sql": ("SQL Injection", "CWE-89", "A03:2021", Severity.HIGH.value),
    "command": ("Command Injection", "CWE-78", "A03:2021", Severity.CRITICAL.value),
    "eval": ("Code Injection", "CWE-95", "A03:2021", Severity.HIGH.value),
    "deserialization": ("Insecure Deserialization", "CWE-502", "A08:2021", Severity.HIGH.value),
    "file": ("Path Traversal", "CWE-22", "A01:2021", Severity.HIGH.value),
}

SINK_RECOMMENDATIONS: dict[str, str] = {
    "sql": "Use parameterised queries / prepared statements; never splice untrusted "
           "input into SQL text.",
    "command": "Do not build shell commands from untrusted input. Pass arguments as a "
               "list with shell execution disabled, and allow-list permitted values.",
    "eval": "Remove dynamic evaluation of untrusted input; use an explicit parser or a "
            "mapping of permitted operations.",
    "deserialization": "Deserialise only into explicit typed schemas from trusted "
                       "sources; never load untrusted data with a general-purpose loader.",
    "file": "Resolve and canonicalise the path, then verify it stays inside the intended "
            "base directory before opening it.",
}

#: Algorithms that are broken/deprecated today — distinct from the quantum
#: lens, which the quantum engine owns.
BROKEN_ALGORITHMS: dict[str, tuple[str, str]] = {
    "MD5": (Severity.HIGH.value, "MD5 is collision-broken and unfit for any security use."),
    "MD4": (Severity.HIGH.value, "MD4 is fully broken."),
    "SHA-1": (Severity.HIGH.value, "SHA-1 is collision-broken and deprecated by NIST."),
    "DES": (Severity.HIGH.value, "DES has a 56-bit key and is brute-forceable."),
    "3DES": (Severity.MEDIUM.value, "3DES is deprecated (SP 800-131A) and has 64-bit blocks."),
    "RC4": (Severity.HIGH.value, "RC4 has practical plaintext-recovery attacks."),
    "Blowfish": (Severity.MEDIUM.value, "Blowfish has 64-bit blocks; prefer AES-GCM."),
}

WEAK_HASH_FOR_PASSWORDS = {"MD5", "SHA-1", "SHA-256", "SHA-512"}

#: TLS/certificate verification disabled — symbol-level, all languages.
INSECURE_TRANSPORT = re.compile(
    r"(?i)(danger_accept_invalid_certs|danger_accept_invalid_hostnames|"
    r"_create_unverified_context|check_hostname|verify\s*=\s*False|"
    r"setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|X509TrustManager|"
    r"trustAllCerts|TrustAllX509TrustManager|NoopHostnameVerifier|"
    r"rejectUnauthorized|InsecureSkipVerify|set_verify)")

WEAK_TLS_VERSIONS = {"SSLv3", "TLS1.0/1.1"}

INSECURE_RANDOM = re.compile(
    r"(?i)(^|\.)(random\.random|random\.randint|random\.choice|Math\.random|"
    r"thread_rng|rand::random|Random\.next|new\s+Random)(\.|$|\()")

SECURITY_SENSITIVE_CONTEXT = re.compile(
    r"(?i)(token|secret|key|password|passwd|nonce|salt|otp|session|csrf|"
    r"uuid|api_?key|credential|seed|iv\b)")

SENSITIVE_LOG_ARGUMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api_?key|token|cvv|pin|ssn|"
    r"card_?number|pan|iban|account_?number|private_?key|authorization)\b")

LOGGING_SYMBOLS = re.compile(
    r"(?i)(^|\.)(log|logger|logging|console|println|print|printf|debug|info|"
    r"warn|warning|error|trace|dbg)(\.|$)")

XSS_SINKS = re.compile(
    r"(?i)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|"
    r"insertAdjacentHTML|v-html|getWriter|\.html\()")

#: Secret detection (regex + entropy, per design note above).
SECRET_ASSIGNMENT = re.compile(
    r'(?i)\b([A-Za-z_][\w\-]*(?:key|secret|token|password|passwd|pwd|credential)'
    r'[\w\-]*)\s*[:=]\s*["\']([^"\'\s]{4,200})["\']')
#: Documentation placeholders. Reporting these trains people to ignore the
#: secret detector, which is worse than missing one.
PLACEHOLDER_SECRET = re.compile(
    r"(?i)^("
    r"(?:your|my|the|some|a)[\w\-]*"                 # your-api-key-here
    r"|change[_\-]?me[\w\-]*|placeholder[\w\-]*"
    r"|(?:example|sample|test|dummy|fake|mock|demo|foo|bar)[\w\-]*"
    r"|[\w\-]*(?:goes[_\-]?here|here|todo|tbd|fixme)"
    r"|x{3,}|\*{3,}|\.{3,}|-{3,}"
    r"|none|null|nil|undefined|true|false|localhost"
    r"|\$\{.*\}|<.*>|\{\{.*\}\}|%\(.*\)s"            # template interpolation
    r")$")


class SecurityEngine(BaseEngine):
    """UST-driven SAST. Deterministic: no model is consulted here."""

    name = ENGINE_NAME

    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH) -> None:
        self.rules = load_rule_catalog(rules_path)

    # ------------------------------------------------------------------
    def analyze(self, context: AnalysisContext) -> EngineResult:
        evidence: list[Evidence] = []
        findings: list[Finding] = []

        for ust_file in context.ust:
            if not ust_file.nodes:
                continue
            try:
                file_evidence, file_findings = self._analyze_file(ust_file, context)
            except Exception as exc:  # noqa: BLE001 — one bad file, not one bad scan
                log.debug("security analysis failed for %s: %s", ust_file.path, exc)
                context.record_error(f"{self.name}:{ust_file.path}", exc)
                continue
            evidence.extend(file_evidence)
            findings.extend(file_findings)

        findings = _dedupe_findings(findings)

        # Apply precision vs recall mode filtering
        scan_mode = getattr(context.config, "scan_mode", "precision") if hasattr(context, "config") else "precision"
        if scan_mode == "precision":
            # Filter out low-confidence findings (< 0.70) without taint flow or severity
            findings = [
                f for f in findings
                if f.tainted or f.is_exploitable or f.confidence >= 0.7 or f.severity in (Severity.CRITICAL.value, Severity.HIGH.value)
            ]

        return EngineResult(evidence=evidence, findings=findings,
                            output={"files_analyzed": len(context.ust.files),
                                    "findings": len(findings)})

    # ------------------------------------------------------------------
    def _analyze_file(self, ust_file: USTFile,
                      context: AnalysisContext) -> tuple[list[Evidence], list[Finding]]:
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        # regex-parsed files are weaker ground; discount their confidence
        parser_penalty = 0.75 if ust_file.parser == "regex" else 1.0

        for node in ust_file.nodes:
            for producer in (self._taint_finding, self._weak_crypto_finding,
                             self._insecure_transport_finding, self._insecure_random_finding,
                             self._sensitive_logging_finding, self._xss_finding):
                produced = producer(node, ust_file, parser_penalty)
                if produced is None:
                    continue
                node_evidence, finding = produced
                evidence.extend(node_evidence)
                if finding is not None:
                    finding.evidence_ids = [e.fingerprint for e in node_evidence]
                    # Reachability / Taint Analysis scoring
                    if finding.tainted:
                        finding.is_exploitable = True
                        finding.exploitability_score = round(min(1.0, finding.confidence * 1.1), 2)
                        finding.exploit_scenario = (
                            f"Untrusted input reaches dangerous sink '{node.symbol}' at line {node.line}. "
                            f"An attacker can exploit this via HTTP/API inputs."
                        )
                    findings.append(finding)

            evidence.extend(self._structural_evidence(node, ust_file))

        secret_evidence, secret_findings = self._secret_scan(ust_file, context)
        evidence.extend(secret_evidence)
        findings.extend(secret_findings)

        return evidence, findings

    # -- detectors -------------------------------------------------------
    def _taint_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        sink = node.data_flow.get("sink")
        if not sink or not node.data_flow.get("tainted"):
            return None
        spec = SINK_CATEGORIES.get(sink)
        if spec is None:
            return None
        category, cwe, owasp, severity = spec
        tainted_vars = node.data_flow.get("tainted_variables", [])
        function = node.enclosing_function or (
            f.name if (f := ust_file.function_at(node.line)) else "")

        ev = Evidence(
            type=EvidenceType.TAINT_FLOW,
            source=DETECTOR,
            file=ust_file.path,
            line=node.line,
            end_line=node.span.end_line,
            column=node.column,
            language=ust_file.language,
            symbol=function or node.symbol,
            operation=f"untrusted input reaches {sink} sink {node.symbol}",
            description=(f"Data-flow analysis traced {', '.join(tainted_vars) or 'input'} "
                         f"into {node.symbol} through dynamic string construction."),
            snippet=node.snippet,
            confidence=round(0.9 * penalty, 2),
            severity_hint=severity,
            node_id=node.node_id,
            tags=["taint", f"sink:{sink}", category],
            metadata={"tainted_variables": tainted_vars,
                      "dynamic_expression": node.data_flow.get("dynamic_expression", False)},
        )
        finding = self._finding(
            category=category, severity=severity, node=node, ust_file=ust_file,
            rule_id=f"UST-{sink.upper()[:4]}-001", cwe=cwe, owasp=owasp,
            confidence=round(0.9 * penalty, 2), tainted=True, function=function,
            reason=(f"Untrusted value {', '.join(tainted_vars) or ''} flows into "
                    f"{node.symbol} without sanitisation.").replace("  ", " "),
            recommendation=SINK_RECOMMENDATIONS.get(sink, f"Mitigate {category}."))
        return [ev], finding

    def _weak_crypto_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        if not node.crypto_tags or "crypto" not in node.crypto_tags:
            return None
        algorithm = _tag_value(node.crypto_tags, "algorithm")
        mode = _tag_value(node.crypto_tags, "mode")
        operation = _tag_value(node.crypto_tags, "operation")

        broken = BROKEN_ALGORITHMS.get(algorithm)
        ecb = mode == "ECB"
        if not broken and not ecb:
            return None

        if broken:
            severity, rationale = broken
        else:
            severity, rationale = (Severity.MEDIUM.value,
                                   "ECB mode is deterministic and leaks plaintext structure.")

        # A broken hash used for integrity checksums is less severe than the
        # same hash protecting a password; say which one we saw.
        password_context = bool(SECURITY_SENSITIVE_CONTEXT.search(
            f"{node.enclosing_function} {node.enclosing_class} {' '.join(node.arguments)}"))
        if algorithm in WEAK_HASH_FOR_PASSWORDS and password_context:
            severity = Severity.HIGH.value

        ev = Evidence(
            type=EvidenceType.CRYPTO_USAGE,
            source=DETECTOR,
            file=ust_file.path, line=node.line, column=node.column,
            end_line=node.span.end_line,
            language=ust_file.language,
            symbol=node.enclosing_function or node.symbol,
            operation=f"{algorithm} {operation}".strip(),
            description=rationale,
            snippet=node.snippet,
            confidence=round(0.95 * penalty, 2),
            severity_hint=severity,
            node_id=node.node_id,
            tags=["crypto", "weak_crypto", f"algorithm:{algorithm}"] + ([f"mode:{mode}"] if mode else []),
            metadata={"algorithm": algorithm, "mode": mode, "operation": operation,
                      "api": node.symbol},
        )
        finding = self._finding(
            category="Weak Crypto", severity=severity, node=node, ust_file=ust_file,
            rule_id=f"UST-CRYPTO-{(algorithm or 'ECB').replace('-', '')}",
            cwe="CWE-327", owasp="A02:2021",
            confidence=round(0.95 * penalty, 2),
            function=node.enclosing_function,
            reason=f"{node.symbol} performs {operation or 'a crypto operation'} with "
                   f"{algorithm or mode}. {rationale}",
            recommendation=(
                "Use SHA-256 or stronger for hashing (Argon2id/bcrypt/scrypt for passwords), "
                "and AES-256-GCM for symmetric encryption."))
        return [ev], finding

    def _insecure_transport_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        if node.symbol in ("re.compile", "re.search", "re.match", "re.sub", "re.subn", "re.finditer", "re.findall", "RegExp") or "replace" in (node.symbol or "").lower():
            return None
        subject = f"{node.symbol} {' '.join(node.arguments)}"
        tls_version = _tag_value(node.crypto_tags, "algorithm")
        weak_version = tls_version in WEAK_TLS_VERSIONS
        disabled_verification = bool(INSECURE_TRANSPORT.search(subject))
        if not weak_version and not disabled_verification:
            return None
        # `rejectUnauthorized: true` / `verify=True` are the secure spelling
        if disabled_verification and re.search(r"(?i)(rejectUnauthorized|check_hostname|"
                                               r"InsecureSkipVerify|verify)\s*[:=]\s*(true|True)",
                                               subject):
            return None

        detail = ("TLS certificate/hostname verification appears disabled"
                  if disabled_verification else f"Deprecated TLS version {tls_version}")
        severity = Severity.CRITICAL.value if disabled_verification else Severity.MEDIUM.value

        ev = Evidence(
            type=EvidenceType.INSECURE_CONFIGURATION,
            source=DETECTOR,
            file=ust_file.path, line=node.line, column=node.column,
            language=ust_file.language,
            symbol=node.enclosing_function or node.symbol,
            operation="insecure transport configuration",
            description=f"{detail} at {node.symbol}.",
            snippet=node.snippet,
            confidence=round(0.8 * penalty, 2),
            severity_hint=severity,
            node_id=node.node_id,
            tags=["tls", "transport_security"],
            metadata={"api": node.symbol, "tls_version": tls_version},
        )
        finding = self._finding(
            category="Broken Authentication", severity=severity, node=node,
            ust_file=ust_file, rule_id="UST-TLS-001", cwe="CWE-295", owasp="A07:2021",
            confidence=round(0.8 * penalty, 2), function=node.enclosing_function,
            reason=f"{detail} at {node.symbol}.",
            recommendation="Keep certificate and hostname verification enabled and require "
                           "TLS 1.2+ (prefer TLS 1.3).")
        return [ev], finding

    def _insecure_random_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        if node.type not in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION):
            return None
        if not INSECURE_RANDOM.search(node.symbol or ""):
            return None
        context_text = " ".join(filter(None, [
            node.enclosing_function, node.enclosing_class, node.snippet]))
        if not SECURITY_SENSITIVE_CONTEXT.search(context_text):
            return None   # a non-crypto random number is not a finding

        ev = Evidence(
            type=EvidenceType.VULNERABILITY_PATTERN,
            source=DETECTOR,
            file=ust_file.path, line=node.line, column=node.column,
            language=ust_file.language,
            symbol=node.enclosing_function or node.symbol,
            operation="non-cryptographic RNG in security context",
            description=f"{node.symbol} is not a CSPRNG but is used where a "
                        f"secret/token/key is produced.",
            snippet=node.snippet,
            confidence=round(0.7 * penalty, 2),
            severity_hint=Severity.MEDIUM.value,
            node_id=node.node_id,
            tags=["random", "crypto"],
            metadata={"api": node.symbol},
        )
        finding = self._finding(
            category="Weak Crypto", severity=Severity.MEDIUM.value, node=node,
            ust_file=ust_file, rule_id="UST-RAND-001", cwe="CWE-338", owasp="A02:2021",
            confidence=round(0.7 * penalty, 2), function=node.enclosing_function,
            reason=f"{node.symbol} is a predictable PRNG used in a security-sensitive "
                   f"context ({node.enclosing_function or ust_file.path}).",
            recommendation="Use a cryptographically secure RNG (secrets/os.urandom, "
                           "SecureRandom, crypto.randomBytes, OsRng).")
        return [ev], finding

    def _sensitive_logging_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        if node.type is not USTNodeType.CALL:
            return None
        if not LOGGING_SYMBOLS.search(node.symbol or ""):
            return None
        arg_text = " ".join(node.arguments)
        match = SENSITIVE_LOG_ARGUMENT.search(arg_text)
        if not match:
            return None

        ev = Evidence(
            type=EvidenceType.VULNERABILITY_PATTERN,
            source=DETECTOR,
            file=ust_file.path, line=node.line, column=node.column,
            language=ust_file.language,
            symbol=node.enclosing_function or node.symbol,
            operation="sensitive value passed to a logging call",
            description=f"{node.symbol} receives '{match.group(0)}'.",
            snippet=node.snippet,
            confidence=round(0.75 * penalty, 2),
            severity_hint=Severity.HIGH.value,
            node_id=node.node_id,
            tags=["logging", "pii", "secret"],
            metadata={"api": node.symbol, "matched_term": match.group(0)},
        )
        finding = self._finding(
            category="Sensitive Logging", severity=Severity.HIGH.value, node=node,
            ust_file=ust_file, rule_id="UST-LOG-001", cwe="CWE-532", owasp="A09:2021",
            confidence=round(0.75 * penalty, 2), function=node.enclosing_function,
            reason=f"'{match.group(0)}' is passed to {node.symbol}, so it can reach log "
                   f"storage and aggregation systems in clear text.",
            recommendation="Redact or mask sensitive fields before logging; log identifiers "
                           "rather than values.")
        return [ev], finding

    def _xss_finding(self, node: USTNode, ust_file: USTFile, penalty: float):
        if node.type not in (USTNodeType.ASSIGNMENT, USTNodeType.CALL):
            return None
        subject = f"{node.symbol} {node.name}"
        if not XSS_SINKS.search(subject):
            return None
        value = " ".join(node.arguments)
        dynamic = node.data_flow.get("tainted") or _is_dynamic(value)
        if not dynamic:
            return None
        severity = Severity.HIGH.value if node.data_flow.get("tainted") else Severity.MEDIUM.value

        ev = Evidence(
            type=EvidenceType.VULNERABILITY_PATTERN,
            source=DETECTOR,
            file=ust_file.path, line=node.line, column=node.column,
            language=ust_file.language,
            symbol=node.enclosing_function or node.symbol,
            operation="dynamic value written to an HTML sink",
            description=f"{node.symbol or node.name} is assigned a dynamically built value.",
            snippet=node.snippet,
            confidence=round(0.7 * penalty, 2),
            severity_hint=severity,
            node_id=node.node_id,
            tags=["xss", "sink:html"],
            metadata={"api": node.symbol or node.name},
        )
        finding = self._finding(
            category="XSS", severity=severity, node=node, ust_file=ust_file,
            rule_id="UST-XSS-001", cwe="CWE-79", owasp="A03:2021",
            confidence=round(0.7 * penalty, 2), function=node.enclosing_function,
            reason=f"A dynamically constructed value reaches the HTML sink "
                   f"{node.symbol or node.name}.",
            recommendation="Render via a templating engine with contextual auto-escaping, "
                           "or sanitise with a vetted HTML sanitiser before insertion.")
        return [ev], finding

    # -- structural evidence (consumed by business intent / risk) --------
    def _structural_evidence(self, node: USTNode, ust_file: USTFile) -> list[Evidence]:
        out: list[Evidence] = []
        common = dict(source=DETECTOR, file=ust_file.path, line=node.line,
                      column=node.column, language=ust_file.language,
                      snippet=node.snippet, node_id=node.node_id, confidence=1.0)

        if "authorization_check" in node.business_tags:
            out.append(Evidence(
                type=EvidenceType.AUTHORIZATION_CHECK,
                symbol=node.enclosing_function or node.symbol,
                operation=f"authorization check via {node.symbol or node.name}",
                description=f"{node.symbol or node.name} performs an access-control check.",
                tags=["authorization"] + node.business_tags, **common))
        if "api_endpoint" in node.business_tags:
            out.append(Evidence(
                type=EvidenceType.API_ENDPOINT,
                symbol=node.enclosing_function or node.symbol,
                operation=f"HTTP route declared via {node.symbol or node.name}",
                description=f"Route handler exposed by {node.symbol or node.name}"
                            + (f": {node.literals[0]}" if node.literals else ""),
                tags=["endpoint"] + node.business_tags,
                metadata={"route": node.literals[0] if node.literals else ""}, **common))
        if "database_operation" in node.business_tags:
            out.append(Evidence(
                type=EvidenceType.DATABASE_OPERATION,
                symbol=node.enclosing_function or node.symbol,
                operation=f"database operation via {node.symbol}",
                description=f"{node.symbol} performs a persistence operation.",
                tags=["database"] + node.business_tags, **common))
        return out

    # -- secrets (regex + entropy, intentionally not UST-typed) ----------
    def _secret_scan(self, ust_file: USTFile,
                     context: AnalysisContext) -> tuple[list[Evidence], list[Finding]]:
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        source = context.repository.read(Path(context.repository.root) / ust_file.path)
        if not source:
            return evidence, findings

        rule = self.rules.get("Hardcoded Secret", {})
        seen_lines: set[int] = set()

        for lineno, line in enumerate(source.splitlines(), 1):
            match = SECRET_ASSIGNMENT.search(line)
            if not match or lineno in seen_lines:
                continue
            name, value = match.group(1), match.group(2)
            if name.lower() in ("foreign_key", "primary_key", "sort_key", "partition_key", "cache_key", "routing_key"):
                continue
            if PLACEHOLDER_SECRET.match(value) or not entropy_gate(name, value):
                continue
            if _is_env_lookup(line):
                continue
            seen_lines.add(lineno)

            function = ""
            enclosing = ust_file.function_at(lineno)
            if enclosing is not None:
                function = enclosing.name

            ev = Evidence(
                type=EvidenceType.SECRET,
                source="regex_secret_scanner",
                file=ust_file.path, line=lineno,
                language=ust_file.language,
                symbol=function or name,
                operation=f"hardcoded credential assigned to '{name}'",
                description=f"A high-entropy literal is assigned to '{name}' in source.",
                snippet=line.strip()[:200],
                confidence=0.85,
                severity_hint=rule.get("severity", Severity.HIGH.value),
                tags=["secret", "credential"],
                metadata={"variable": name, "value_length": len(value)},
            )
            evidence.append(ev)
            findings.append(Finding(
                category="Hardcoded Secret",
                severity=rule.get("severity", Severity.HIGH.value),
                rule_id=rule.get("rule_id", "UST-SECRET-001"),
                file=ust_file.path, line=lineno,
                snippet=line.strip()[:200],
                recommendation=rule.get(
                    "recommendation",
                    "Load credentials from environment variables or a secret manager; "
                    "rotate any value that reached version control."),
                cwe="CWE-798", owasp="A07:2021",
                confidence=0.85,
                language=ust_file.language, function=function,
                evidence_ids=[ev.fingerprint], source="DETERMINISTIC",
                reason=f"'{name}' is assigned a high-entropy literal in source code.",
                engine=self.name,
            ))
        return evidence, findings

    # -- helper ----------------------------------------------------------
    def _finding(self, *, category: str, severity: str, node: USTNode, ust_file: USTFile,
                 rule_id: str, cwe: str, owasp: str, confidence: float,
                 reason: str, recommendation: str, function: str = "",
                 tainted: bool = False) -> Finding:
        rule = self.rules.get(category, {})
        return Finding(
            category=category,
            severity=rule.get("severity_override", severity),
            rule_id=rule.get("rule_id") or rule_id,
            file=ust_file.path,
            line=node.line,
            snippet=node.snippet[:200],
            recommendation=rule.get("recommendation_override") or recommendation,
            cwe=cwe, owasp=owasp,
            confidence=confidence,
            tainted=tainted,
            language=ust_file.language,
            function=function or node.enclosing_function,
            end_line=node.span.end_line,
            column=node.column,
            source="DETERMINISTIC",
            reason=reason,
            engine=self.name,
        )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a location+category, keeping the most
    confident one and unioning their evidence. Nested expressions can
    legitimately produce several UST nodes on one line."""
    best: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.category)
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            continue
        keeper, loser = ((finding, existing)
                         if finding.confidence > existing.confidence
                         else (existing, finding))
        merged = list(dict.fromkeys(keeper.evidence_ids + loser.evidence_ids))
        keeper.evidence_ids = merged
        best[key] = keeper
    return sorted(best.values(), key=lambda f: (f.file, f.line, f.category))


def _tag_value(tags: list[str], key: str) -> str:
    prefix = key + ":"
    for tag in tags:
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return ""


def _is_dynamic(text: str) -> bool:
    return bool(text) and (
        "+" in text or "${" in text or "{}" in text or ".format(" in text
        or "format!" in text or text.strip().isidentifier())


def _is_env_lookup(line: str) -> bool:
    return bool(re.search(r"(?i)(os\.environ|getenv|process\.env|System\.getenv|"
                          r"env::var|dotenv|config\.get|vault)", line))
