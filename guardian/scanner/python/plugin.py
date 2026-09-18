"""Python language plugin — stdlib-AST parsing with per-function taint
tracking (source -> sink, sanitiser-aware) plus entropy-filtered secret
detection. Ported intact from v1."""
from guardian.core.models import Finding
from guardian.core.registry import register_language
from guardian.scanner.base import EngineBackedPlugin
from guardian.scanner.common.treesitter_engine import analyze_python_ast


@register_language
class PythonPlugin(EngineBackedPlugin):
    name = "python"
    extensions = (".py",)
    _engine_language = "python"

    def scan_source(self, source: str, file_label: str) -> list[Finding]:
        findings = super().scan_source(source, file_label)
        # Deep AST Taint pass
        ast_results = analyze_python_ast(source, file_label)
        lines = source.splitlines()
        for cat, sev, lineno, msg, rec in ast_results:
            snip = lines[lineno - 1].strip()[:200] if 0 < lineno <= len(lines) else msg
            if not any(f.line == lineno and f.category == cat for f in findings):
                findings.append(Finding(
                    category=cat, severity=sev, rule_id=f"PY-AST-{cat[:4].upper()}",
                    file=file_label, line=lineno, snippet=snip,
                    recommendation=rec, confidence=0.85,
                ))
        return findings

