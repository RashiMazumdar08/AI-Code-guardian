"""JavaScript/TypeScript language plugin — starter pattern set proving
the registry accepts new languages with zero pipeline changes.
TODO(plugin-roadmap): replace with Tree-sitter AST rules; add DOM XSS
taint tracking; extend to framework-specific sinks (res.send, innerHTML).
"""
from __future__ import annotations

import re

from guardian.core.models import Finding
from guardian.core.registry import register_language
from guardian.scanner.common.secrets import entropy_gate

_PATTERNS = [
    ("SQL Injection", "High", re.compile(r'\.(query|execute)\s*\(\s*[`"\'][^`"\']*[`"\']\s*[\+\$]')),
    ("XSS", "Medium", re.compile(r'(\.innerHTML|\.outerHTML|document\.write)\s*=\s*[^;]*\+')),
    ("XSS", "High", re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:')),
    ("Eval Injection", "High", re.compile(r'\b(eval|setTimeout|setInterval)\s*\(\s*[`"\'][^`"\']*[`"\']\s*\+|\beval\s*\(\s*\w')),
    ("Command Injection", "High", re.compile(r'child_process\.(exec|execSync)\s*\(\s*[`"\'][^`"\']*[`"\']\s*\+')),
    ("Insecure Random", "Low", re.compile(r'Math\.random\s*\(\s*\)')),
    ("Path Traversal", "High", re.compile(r'fs\.(readFile|readFileSync|createReadStream)\s*\(\s*[^,)]*\+')),
]
_SECRET = re.compile(r'(?i)\b(\w*(?:key|secret|token|password))\s*[:=]\s*["\']([^"\']{4,})["\']')


@register_language
class JavaScriptPlugin:
    name = "javascript"
    extensions = (".js", ".jsx", ".ts", ".tsx")

    def scan_source(self, source: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for category, severity, pat in _PATTERNS:
                if pat.search(line):
                    findings.append(Finding(
                        category=category, severity=severity, rule_id=f"JS-{category[:4].upper()}",
                        file=file_label, line=lineno, snippet=stripped[:200],
                        recommendation=f"Mitigate {category} using secure input validation, parameterization, and context-aware escaping.",
                        confidence=0.75,
                    ))
                    break
            m = _SECRET.search(line)
            if m and entropy_gate(m.group(1), m.group(2)):
                findings.append(Finding(
                    category="Hardcoded Secret", severity="High", rule_id="JS-SECRET",
                    file=file_label, line=lineno, snippet=stripped[:200],
                    recommendation="Move secrets to environment variables or a vault.",
                    confidence=0.8,
                ))
        return findings

