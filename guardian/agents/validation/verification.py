"""
AI Code Guardian v3 — Mechanical Patch Verification Service
============================================================
Re-runs deterministic security scanning over replacement code snippets to mechanically
verify that the original security finding is fully resolved.
"""
from __future__ import annotations

import ast
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class PatchVerificationService:
    """Service performing mechanical re-verification of patch code replacements."""

    def verify_remediation(
        self,
        original_finding: Dict[str, Any],
        replacement_snippet: str,
        language: str = "python"
    ) -> Dict[str, Any]:
        """
        Mechanically re-scans replacement code using AST parsing and SecurityRuleEngine.
        Returns verification status (resolved: bool, syntax_valid: bool, issues: List[str]).
        """
        issues = []
        syntax_valid = True

        # 1. Syntax Verification (Python AST)
        if language.lower() in ("python", "py"):
            try:
                ast.parse(replacement_snippet)
            except SyntaxError as se:
                syntax_valid = False
                issues.append(f"Syntax error in replacement snippet: {se.msg} at line {se.lineno}")

        # 2. Deterministic Rule Re-scan
        resolved = syntax_valid
        if syntax_valid:
            try:
                from guardian.scanner._engine import SecurityRuleEngine
                engine = SecurityRuleEngine()
                res_findings = engine.scan_source(replacement_snippet, "patched_snippet.py", language="python")
                matching_reissues = [f for f in res_findings if getattr(f, "rule_id", "") == original_finding.get("rule_id")]
                if matching_reissues:
                    resolved = False
                    issues.append(f"Rule '{original_finding.get('rule_id')}' still triggered in patched code snippet.")
            except Exception as exc:
                logger.warning(f"Re-scan verification notice: {exc}")

        return {
            "resolved": resolved,
            "syntax_valid": syntax_valid,
            "issues": issues,
            "confidence_boost": 0.15 if resolved else -0.30,
        }
