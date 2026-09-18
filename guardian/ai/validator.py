"""
AI Assistant — Response Validator
=================================
Mechanical hallucination detection. The grounding rule in the system
prompt is a *request*; this module is the *enforcement*. Every claim in
an LLM answer that is cheap to verify gets verified:

    * file paths the answer references must exist in the scanned repo
    * `file:line` references must be within the file's actual length
    * finding/rule IDs the answer cites must exist in the scan report

The validator never blocks an answer (small local models paraphrase
paths in ways that legitimately fail strict checks); it returns a
verdict the pipeline uses to (a) append an explicit unverified-claims
warning and (b) mark the response as ungrounded so the UI can badge it.

This implements the "Output Validation" stage promised in the Master
Design Document §9.1, which previously did not exist — the primary
cause of user-visible hallucination.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# path-ish token, optionally followed by :line — matches `crates/x/src/a.rs:47`,
# `payments/order.py`, backtick-wrapped or bare.
_FILE_REF = re.compile(
    r'(?<![\w/])((?:[\w.\-]+/)+[\w.\-]+\.[A-Za-z]{1,5}|[\w.\-]+\.(?:py|java|rs|js|jsx|ts|tsx|go|kt|rb|php|tf|ya?ml|json|toml))'
    r'(?::(\d{1,6}))?')
_RULE_REF = re.compile(r'\b((?:ACG|RS|JS|IAC|DEP|QNT|SEC)-[A-Z0-9]+-?\d*)\b')
_LINE_PHRASE = re.compile(r'\b[Ll]ine\s+(\d{1,6})\b(?:\s+(?:of|in)\s+[`"]?([\w./\-]+)[`"]?)?')

_IGNORE_FILE_TOKENS = {"requirements.txt", "package.json", "pom.xml", "go.mod",
                       "config.yaml", "example.py", "example.java"}


@dataclass
class ValidationResult:
    ok: bool
    violations: list[str] = field(default_factory=list)
    checked_refs: int = 0

    def warning_block(self) -> str:
        if self.ok:
            return ""
        bullets = "\n".join(f"  - {v}" for v in self.violations[:6])
        return ("\n\n---\n⚠️ **Unverified references** — the following claims could not be "
                "confirmed against the scanned repository and may be inaccurate:\n" + bullets)


class ResponseValidator:
    """Validates one LLM answer against a repo root and/or a scan report dict."""

    def __init__(self, repo_root: Optional[str | Path] = None,
                 scan_report: Optional[dict] = None):
        self.repo_root = Path(repo_root) if repo_root else None
        self._known_rules: set[str] = set()
        self._known_files: set[str] = set()
        self._scan_report: Optional[dict] = scan_report
        if scan_report:
            self.load_report(scan_report)

    def load_report(self, scan_report: dict) -> None:
        self._scan_report = scan_report
        for f in scan_report.get("scan", {}).get("findings", []):
            if f.get("rule_id"):
                self._known_rules.add(str(f["rule_id"]))
            if f.get("file"):
                self._known_files.add(str(f["file"]).replace("\\", "/"))

    # ------------------------------------------------------------------
    def validate(self, answer: str) -> ValidationResult:
        violations: list[str] = []
        checked = 0

        # 1. file[:line] references
        for m in _FILE_REF.finditer(answer):
            ref, line_s = m.group(1), m.group(2)
            if ref in _IGNORE_FILE_TOKENS:
                continue
            checked += 1
            resolved = self._resolve(ref)
            if resolved is None and ref.replace("\\", "/") not in self._known_files:
                violations.append(f"file `{ref}` does not exist in the scanned repository")
                continue
            if line_s and resolved is not None:
                line = int(line_s)
                n_lines = self._line_count(resolved)
                if n_lines is not None and line > n_lines:
                    violations.append(
                        f"`{ref}:{line}` is out of range (file has {n_lines} lines)")

        # 2. "line N of file" phrasing
        for m in _LINE_PHRASE.finditer(answer):
            line, ref = int(m.group(1)), m.group(2)
            if not ref:
                continue
            checked += 1
            resolved = self._resolve(ref)
            if resolved is not None:
                n_lines = self._line_count(resolved)
                if n_lines is not None and line > n_lines:
                    violations.append(
                        f"line {line} of `{ref}` is out of range (file has {n_lines} lines)")

        # 3. rule IDs
        if self._known_rules:
            for m in _RULE_REF.finditer(answer):
                checked += 1
                if m.group(1) not in self._known_rules:
                    violations.append(
                        f"rule `{m.group(1)}` does not appear in the scan report")

        # 4. semantic check — the mechanical checks above only verify that
        # referenced files/lines/rules exist; they don't catch an answer
        # that names a real file but describes the wrong vulnerability
        # category for it (e.g. calling a Hardcoded Secret finding "SQL
        # Injection"). Flag that mismatch too.
        semantic_issue = self._semantic_mismatch(answer)
        if semantic_issue:
            violations.append(semantic_issue)

        return ValidationResult(ok=not violations, violations=violations,
                                checked_refs=checked)

    def _semantic_mismatch(self, text: str) -> Optional[str]:
        """Return a violation message if the answer discusses a file that
        appears in the scan report but none of that file's actual finding
        categories are mentioned anywhere in the answer."""
        report = self._scan_report
        if not report or "scan" not in report:
            return None
        text_lower = text.lower()
        for finding in report.get("scan", {}).get("findings", []):
            category = str(finding.get("category") or "")
            file_path = str(finding.get("file") or "").replace("\\", "/")
            if not file_path or not category:
                continue
            if file_path not in text and file_path not in text.replace("\\", "/"):
                continue
            expected_keywords = [kw for kw in category.lower().split() if len(kw) > 2]
            if expected_keywords and not any(kw in text_lower for kw in expected_keywords):
                return (f"the answer discusses `{file_path}` but does not mention its "
                        f"actual finding category (`{category}`) — the description may not "
                        f"match the scan data")
        return None

    # ------------------------------------------------------------------
    def _resolve(self, ref: str) -> Optional[Path]:
        if self.repo_root is None:
            return None
        cand = (self.repo_root / ref)
        if cand.is_file():
            return cand
        # answers often use repo-relative paths one level off; try a
        # bounded suffix search before declaring it fabricated
        parts = Path(ref).parts
        if len(parts) >= 1:
            hits = list(self.repo_root.glob(f"**/{parts[-1]}"))
            for h in hits[:50]:
                if str(h).replace("\\", "/").endswith(ref.replace("\\", "/")):
                    return h
        return None

    @staticmethod
    def _line_count(path: Path) -> Optional[int]:
        try:
            with open(path, "rb") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return None
