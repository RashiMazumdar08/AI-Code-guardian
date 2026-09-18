"""
AI Code Guardian - Security Rule Engine
========================================
scan_source() / scan_file() / scan_directory() entry points.

Design notes carried over from Days 1-4:
- Python: real `ast` module parsing + lightweight taint tracking
  (source -> sink, sanitiser-aware) per function.
- Java: regex bridge until the Tree-sitter UAST (Days 2-3) is fully wired
  into rule matching. Patterns cover camelCase AND SCREAMING_SNAKE_CASE
  identifiers for secret detection.
- Hardcoded-secret detection uses Shannon entropy (threshold 2.8, tuned
  down from 3.2) to admit structured keys like SECRET_KEY_1 while still
  filtering low-entropy constant-name-only false positives.
"""
from __future__ import annotations

import ast
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from guardian.core.models import Finding, ScanResult, Severity

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "rules" / "Security_Rules.json"

ENTROPY_THRESHOLD = 2.8

# Recognised taint sources / sinks / sanitisers for the Python taint pass.
PY_SOURCE_FUNCS = {"input", "request.args.get", "request.form.get", "os.environ.get", "getenv"}
PY_SQL_SINKS = {"execute", "executemany", "raw", "executescript"}
PY_CMD_SINKS = {"system", "popen", "call", "run", "check_output"}
PY_EVAL_SINKS = {"eval", "exec"}
PY_SANITISERS = {"escape", "quote", "parameterize", "sanitize"}


# --------------------------------------------------------------------------
# Shared utilities
# --------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_rules(rules_path: Path = DEFAULT_RULES_PATH) -> dict:
    if not rules_path.exists():
        return {}
    with open(rules_path) as f:
        return {r["category"]: r for r in json.load(f)}


# --------------------------------------------------------------------------
# Java regex-bridge detectors
# --------------------------------------------------------------------------
JAVA_PATTERNS: dict[str, list[re.Pattern]] = {
    "SQL Injection": [
        re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\b[^;"]*"\s*\+\s*\w+', re.I),
        re.compile(r'\.execute(Query|Update)?\s*\(\s*"[^"]*"\s*\+'),
    ],
    "XSS": [
        re.compile(r'response\.getWriter\(\)\.print\([^)]*\+\s*request\.getParameter'),
        re.compile(r'\.innerHTML\s*=\s*[^;]*\+\s*\w+'),
    ],
    "Hardcoded Secret": [
        # Covers both apiKey="..." (camelCase) and API_KEY="..." (SCREAMING_SNAKE_CASE)
        re.compile(r'(?i)\b([a-z][a-zA-Z0-9]*(?:Key|Secret|Token|Password)|[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD))\s*=\s*"([^"]{4,})"'),
    ],
    "Weak Crypto": [
        re.compile(r'\bDES\b|\bMD5\b|\bSHA-?1\b|\bRC4\b'),
        re.compile(r'Cipher\.getInstance\(\s*"(DES|RC4|AES/ECB)'),
    ],
    "Broken Authentication": [
        re.compile(r'X509TrustManager\(\)\s*\{'),
        re.compile(r'\btrustAllCerts\b'),
        re.compile(r'HostnameVerifier\(\)\s*\{[^}]*return\s+true'),
    ],
    "Path Traversal": [
        re.compile(r'new\s+File\s*\(\s*\w+\s*\+'),
        re.compile(r'Paths\.get\([^)]*\+\s*\w+'),
    ],
    "Sensitive Logging": [
        re.compile(r'(?:log|LOG|logger)\.\w+\([^)]*\b(password|pin|cvv|ssn|cardNumber|secret)\b', re.I),
    ],
}


def _scan_java_text(text: str, file_label: str, rules: dict) -> list[Finding]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for category, patterns in JAVA_PATTERNS.items():
            for pat in patterns:
                m = pat.search(line)
                if not m:
                    continue
                if category == "Hardcoded Secret":
                    var_name = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                    value = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                    normalized_name = re.sub(r'[_\W]', '', var_name).lower()
                    normalized_value = re.sub(r'[_\W]', '', value).lower()
                    if normalized_value == normalized_name:
                        continue  # e.g. SMTP_PASSWORD = "SMTP_PASSWORD" -> a constant label, not a secret
                    if shannon_entropy(value) < ENTROPY_THRESHOLD and not re.search(r'\d', value):
                        continue
                rule = rules.get(category, {})
                findings.append(Finding(
                    category=category,
                    severity=rule.get("severity", Severity.MEDIUM.value),
                    rule_id=rule.get("rule_id"),
                    file=file_label,
                    line=lineno,
                    snippet=line.strip()[:200],
                    recommendation=rule.get("recommendation", f"Mitigate {category}."),
                    confidence=0.6,   # regex bridge -> lower confidence than AST/taint
                    tainted=False,
                ))
                break
    return findings


# --------------------------------------------------------------------------
# Python AST + taint detectors
# --------------------------------------------------------------------------
class _PyTaintVisitor(ast.NodeVisitor):
    """Per-function taint tracking: marks variables assigned from a source
    as tainted, propagates through simple assignments/concatenation, and
    flags any tainted value reaching a recognised sink without sanitisation.
    """

    def __init__(self, file_label: str, rules: dict, source_lines: list[str]):
        self.file_label = file_label
        self.rules = rules
        self.source_lines = source_lines
        self.tainted_vars: set[str] = set()
        self.findings: list[Finding] = []

    def _snippet(self, node: ast.AST) -> str:
        try:
            return self.source_lines[node.lineno - 1].strip()[:200]
        except IndexError:
            return ""

    def _call_name(self, node: ast.Call) -> str:
        """Returns the short name (e.g. 'execute') used for sink matching."""
        f = node.func
        if isinstance(f, ast.Attribute):
            return f.attr
        if isinstance(f, ast.Name):
            return f.id
        return ""

    def _call_dotted_name(self, node: ast.Call) -> str:
        """Best-effort dotted chain (e.g. 'request.args.get') for source matching."""
        parts = []
        f = node.func
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        return ".".join(reversed(parts))

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):  # f-strings
            return any(self._expr_is_tainted(v) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            name = self._call_name(node)
            dotted = self._call_dotted_name(node)
            if name in {s.split(".")[-1] for s in PY_SOURCE_FUNCS} and (dotted in PY_SOURCE_FUNCS or name in PY_SOURCE_FUNCS):
                return True
            if name in PY_SANITISERS:
                return False
            return any(self._expr_is_tainted(a) for a in node.args)
        return False

    def visit_Assign(self, node: ast.Assign):
        tainted = self._expr_is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted_vars.add(target.id)
                else:
                    self.tainted_vars.discard(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        full_attr = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            full_attr = f"{node.func.value.id}.{node.func.attr}"

        args_tainted = any(self._expr_is_tainted(a) for a in node.args)

        if name in PY_SQL_SINKS and args_tainted:
            self._emit("SQL Injection", node, confidence=0.95, tainted=True)
        elif (name in PY_CMD_SINKS or full_attr.startswith("os.")) and args_tainted and name in PY_CMD_SINKS:
            self._emit("Command Injection", node, confidence=0.9, tainted=True,
                        fallback_category="SQL Injection")  # map to closest catalog entry if no dedicated rule
        elif name in PY_EVAL_SINKS and args_tainted:
            self._emit("Insecure Deserialization", node, confidence=0.85, tainted=True)
        elif name == "pickle.loads" or full_attr == "pickle.loads":
            self._emit("Insecure Deserialization", node, confidence=0.8, tainted=args_tainted)

        self.generic_visit(node)

    def _emit(self, category: str, node: ast.AST, confidence: float, tainted: bool, fallback_category: Optional[str] = None):
        rule = self.rules.get(category) or (self.rules.get(fallback_category) if fallback_category else None) or {}
        self.findings.append(Finding(
            category=category,
            severity=rule.get("severity", Severity.HIGH.value),
            rule_id=rule.get("rule_id"),
            file=self.file_label,
            line=getattr(node, "lineno", 0),
            snippet=self._snippet(node),
            recommendation=rule.get("recommendation", f"Mitigate {category} using secure coding practices."),
            confidence=confidence,
            tainted=tainted,
        ))


def _scan_python_secrets(text: str, file_label: str, rules: dict) -> list[Finding]:
    findings = []
    pattern = re.compile(r'(?i)\b(\w*(?:key|secret|token|password)\w*)\s*=\s*["\']([^"\']{4,})["\']')
    for lineno, line in enumerate(text.splitlines(), 1):
        m = pattern.search(line)
        if not m:
            continue
        value = m.group(2)
        var_name = m.group(1)
        if var_name.lower() in ("foreign_key", "primary_key", "sort_key", "partition_key", "cache_key", "routing_key"):
            continue
        if re.sub(r'[_\W]', '', value).lower() == re.sub(r'[_\W]', '', var_name).lower():
            continue
        if shannon_entropy(value) < ENTROPY_THRESHOLD and not re.search(r'\d', value):
            continue
        rule = rules.get("Hardcoded Secret", {})
        findings.append(Finding(
            category="Hardcoded Secret",
            severity=rule.get("severity", Severity.HIGH.value),
            rule_id=rule.get("rule_id"),
            file=file_label,
            line=lineno,
            snippet=line.strip()[:200],
            recommendation=rule.get("recommendation", "Mitigate Hardcoded Secret using secure coding practices."),
            confidence=0.85,
        ))
    return findings


def _scan_python_text(text: str, file_label: str, rules: dict) -> list[Finding]:
    if "\x00" in text:
        text = text.replace("\x00", "")
    findings = _scan_python_secrets(text, file_label, rules)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return findings  # fall back to regex-only results for unparsable files
    source_lines = text.splitlines()
    for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        visitor = _PyTaintVisitor(file_label, rules, source_lines)
        # Seed taint for parameters that look like request/user input.
        for arg in func.args.args:
            if re.search(r'(?i)request|input|param|user', arg.arg):
                visitor.tainted_vars.add(arg.arg)
        visitor.visit(func)
        findings.extend(visitor.findings)
    return findings


# --------------------------------------------------------------------------
# Public engine
# --------------------------------------------------------------------------
class SecurityRuleEngine:
    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH):
        self.rules = load_rules(rules_path)

    def scan_source(self, source: str, file_label: str, language: Optional[str] = None) -> list[Finding]:
        lang = language or self._infer_language(file_label)
        if lang == "python":
            return _scan_python_text(source, file_label, self.rules)
        if lang == "java":
            return _scan_java_text(source, file_label, self.rules)
        if lang in ("javascript", "typescript"):
            # Delegate to the dedicated JS/TS pattern set (guardian/scanner/javascript)
            # instead of silently returning no findings for non-Python/Java sources.
            from guardian.scanner.javascript.plugin import JavaScriptPlugin
            return JavaScriptPlugin().scan_source(source, file_label)
        if lang == "rust":
            from guardian.scanner.rust.plugin import RustPlugin
            return RustPlugin().scan_source(source, file_label)
        return []

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        findings = self.scan_source(text, str(path))
        result = ScanResult(target=str(path), files_scanned=1, findings=findings)
        result.finish()
        return result

    def scan_directory(self, root: str | Path,
                        extensions: Iterable[str] = (".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".rs"),
                        exclude_dirs: Iterable[str] = ("test", "tests", "node_modules", ".git")) -> ScanResult:
        root = Path(root)
        all_findings: list[Finding] = []
        files_scanned = 0
        exclude_dirs = set(exclude_dirs)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fn in filenames:
                if Path(fn).suffix not in extensions:
                    continue
                fp = Path(dirpath) / fn
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                all_findings.extend(self.scan_source(text, str(fp.relative_to(root))))
                files_scanned += 1
        result = ScanResult(target=str(root), files_scanned=files_scanned, findings=all_findings)
        result.finish()
        return result

    @staticmethod
    def _infer_language(file_label: str) -> str:
        ext = Path(file_label).suffix.lower()
        return {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".rs": "rust",
        }.get(ext, "unknown")
