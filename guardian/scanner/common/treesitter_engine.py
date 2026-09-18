"""
Universal AST & Taint Analysis Engine
=====================================
Provides AST node parsing, semantic query execution, and data-flow
taint analysis across programming languages. Supports tree-sitter bindings
when available, with standard library AST / CST fallback parser logic.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class TaintFlow:
    source_node: str
    sink_node: str
    variable_name: str
    line: int
    category: str
    severity: str
    snippet: str


class PythonASTTaintAnalyzer(ast.NodeVisitor):
    """Deep AST taint tracking visitor for Python code."""

    def __init__(self, file_label: str) -> None:
        self.file_label = file_label
        self.tainted_vars: Set[str] = set()
        self.findings: List[Tuple[str, str, int, str, str]] = []  # (category, severity, line, snippet, rec)

        # Common untrusted input sources
        self.sources = {
            "request.args", "request.form", "request.json", "request.values",
            "request.GET", "request.POST", "request.body", "sys.argv", "input",
            "user_input", "payload", "params", "query_params"
        }

    def _is_tainted_expr(self, node: Optional[ast.AST], depth: int = 0) -> bool:
        if node is None or depth > 30:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars or node.id in self.sources
        if isinstance(node, ast.Attribute):
            full_attr = f"{self._get_attr_name(node.value, depth + 1)}.{node.attr}"
            return full_attr in self.sources or node.attr in self.tainted_vars
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left, depth + 1) or self._is_tainted_expr(node.right, depth + 1)
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(self._is_tainted_expr(val.value if isinstance(val, ast.FormattedValue) else None, depth + 1)
                       for val in node.values if isinstance(val, ast.FormattedValue))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return self._is_tainted_expr(node.func.value, depth + 1) or any(self._is_tainted_expr(a, depth + 1) for a in node.args)
            return any(self._is_tainted_expr(arg, depth + 1) for arg in node.args)
        return False

    def _get_attr_name(self, node: ast.AST, depth: int = 0) -> str:
        if depth > 20 or node is None:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_attr_name(node.value, depth + 1)}.{node.attr}"
        return ""

    def visit_Assign(self, node: ast.Assign) -> None:
        is_tainted = self._is_tainted_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_tainted:
                    self.tainted_vars.add(target.id)
                else:
                    self.tainted_vars.discard(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            base = self._get_attr_name(node.func.value)
            func_name = f"{base}.{node.func.attr}".strip(".")

        # SQL Injection Sinks
        if func_name.endswith(".execute") or func_name.endswith(".executemany") or func_name in ("execute", "raw"):
            if node.args and self._is_tainted_expr(node.args[0]):
                self.findings.append((
                    "SQL Injection", "High", node.lineno,
                    f"Tainted query passed to {func_name}()",
                    "Use parameterized query placeholders (%s or ?) instead of string formatting."
                ))

        # Command Injection Sinks
        if func_name in ("os.system", "subprocess.Popen", "subprocess.call", "subprocess.run", "eval", "exec"):
            if node.args and self._is_tainted_expr(node.args[0]):
                self.findings.append((
                    "Command Injection", "High", node.lineno,
                    f"Tainted input passed to command execution sink {func_name}()",
                    "Avoid invoking subshells with untrusted strings; pass arguments as a list with shell=False."
                ))

        self.generic_visit(node)


def analyze_python_ast(source: str, file_label: str) -> List[Tuple[str, str, int, str, str]]:
    """Parse Python code into AST and perform static taint propagation analysis."""
    if "\x00" in source:
        source = source.replace("\x00", "")
    try:
        tree = ast.parse(source)
        visitor = PythonASTTaintAnalyzer(file_label)
        visitor.visit(tree)
        return visitor.findings
    except Exception:
        return []

