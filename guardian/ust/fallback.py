"""
UST Fallback Normalizers
========================
Tree-sitter is the primary parsing foundation. This module is what keeps
a scan useful when it is *not* available:

  * `python_ast_ust()`  — the stdlib `ast` path, preserved from v1. It
    yields genuinely structured nodes, so Python coverage is unchanged
    even in an environment with no compiled grammars.
  * `regex_ust()`       — a last-resort line scanner for any language.
    It finds function declarations, imports and call sites well enough
    for the crypto/secret detectors to keep working, and marks the
    resulting USTFile with `parser="regex"` so consumers can discount
    its confidence.

Neither path is a "primary representation": engines consume UST either
way, and `USTFile.parser` records how the nodes were obtained.
"""
from __future__ import annotations

import ast
import logging
import re
from typing import Optional

from guardian.ust.models import SourceSpan, UST, USTFile, USTNode, USTNodeType

log = logging.getLogger(__name__)

MAX_SNIPPET = 240


# ---------------------------------------------------------------------------
# Python stdlib-ast fallback
# ---------------------------------------------------------------------------
class _PyUSTVisitor(ast.NodeVisitor):
    def __init__(self, file_label: str, lines: list[str]) -> None:
        self.file = file_label
        self.lines = lines
        self.nodes: list[USTNode] = []
        self.imports: list[str] = []
        self._fn_stack: list[str] = []
        self._cls_stack: list[str] = []
        self._flags: dict = {}

    # -- helpers -------------------------------------------------------
    def _span(self, node: ast.AST) -> SourceSpan:
        return SourceSpan(
            start_line=getattr(node, "lineno", 0),
            start_column=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", 0) or getattr(node, "lineno", 0),
            end_column=getattr(node, "end_col_offset", 0) or 0,
        )

    def _snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(self.lines):
            return self.lines[line - 1].strip()[:MAX_SNIPPET]
        return ""

    def _emit(self, kind: USTNodeType, node: ast.AST, **kwargs) -> USTNode:
        ust = USTNode(
            type=kind, language="python", file=self.file, span=self._span(node),
            snippet=self._snippet(node),
            enclosing_function=self._fn_stack[-1] if self._fn_stack else "",
            enclosing_class=self._cls_stack[-1] if self._cls_stack else "",
            control_flow={k: v for k, v in self._flags.items() if v},
            metadata={"grammar_type": type(node).__name__},
            **kwargs,
        )
        self.nodes.append(ust)
        return ust

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        elif isinstance(node, ast.Call):
            inner = _PyUSTVisitor._dotted(node.func)
            if inner:
                parts.append(inner)
        return ".".join(reversed(parts))

    @staticmethod
    def _expr_text(node: ast.AST) -> str:
        try:
            return ast.unparse(node)[:160]
        except Exception:  # noqa: BLE001 — unparse fails on exotic trees
            return ""

    # -- visits --------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
            self._emit(USTNodeType.IMPORT, node, name=alias.name, symbol=alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full)
            self._emit(USTNodeType.IMPORT, node, name=full, symbol=full)
        self.generic_visit(node)

    def _visit_function(self, node) -> None:
        name = node.name
        cls = self._cls_stack[-1] if self._cls_stack else ""
        params = [a.arg for a in list(node.args.args) + list(node.args.kwonlyargs)]
        self._emit(USTNodeType.FUNCTION, node, name=name,
                   symbol=f"{cls}.{name}" if cls else name, parameters=params)
        for dec in node.decorator_list:
            self._emit(USTNodeType.ANNOTATION, dec, name=self._dotted(
                dec.func if isinstance(dec, ast.Call) else dec))
        self._fn_stack.append(name)
        self.generic_visit(node)
        self._fn_stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._emit(USTNodeType.CLASS, node, name=node.name, symbol=node.name)
        self._cls_stack.append(node.name)
        self.generic_visit(node)
        self._cls_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        symbol = self._dotted(node.func)
        args = [self._expr_text(a) for a in node.args]
        literals = [a.value for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if symbol:
            self._emit(USTNodeType.CALL, node, name=symbol.rsplit(".", 1)[-1],
                       symbol=symbol, arguments=[a for a in args if a][:12],
                       literals=literals[:12])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target = self._expr_text(node.targets[0]) if node.targets else ""
        value = self._expr_text(node.value)
        literals = ([node.value.value]
                    if isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str) else [])
        self._emit(USTNodeType.ASSIGNMENT, node, name=target, symbol=target,
                   arguments=[value] if value else [], literals=literals)
        self.generic_visit(node)

    def _scoped(self, node, flag: str, kind: USTNodeType) -> None:
        self._emit(kind, node)
        prev = self._flags.get(flag)
        self._flags[flag] = True
        self.generic_visit(node)
        self._flags[flag] = prev

    def visit_If(self, node: ast.If) -> None:
        self._scoped(node, "in_conditional", USTNodeType.CONDITIONAL)

    def visit_For(self, node: ast.For) -> None:
        self._scoped(node, "in_loop", USTNodeType.LOOP)

    def visit_While(self, node: ast.While) -> None:
        self._scoped(node, "in_loop", USTNodeType.LOOP)

    def visit_Try(self, node: ast.Try) -> None:
        self._scoped(node, "in_exception_handler", USTNodeType.EXCEPTION_HANDLING)

    def visit_Raise(self, node: ast.Raise) -> None:
        self._emit(USTNodeType.EXCEPTION_HANDLING, node, name="raise")
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self._emit(USTNodeType.RETURN, node,
                   arguments=[self._expr_text(node.value)] if node.value else [])
        self.generic_visit(node)


def python_ast_ust(source: str, file_label: str) -> Optional[USTFile]:
    """Build a USTFile from Python source using the stdlib parser."""
    if "\x00" in source:
        source = source.replace("\x00", "")
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return USTFile(path=file_label, language="python", parser="python-ast",
                       parse_error=f"syntax error: {exc}", line_count=len(lines))
    visitor = _PyUSTVisitor(file_label, lines)
    visitor.visit(tree)
    visitor.nodes.sort(key=lambda n: (n.span.start_line, n.span.start_column))
    return USTFile(path=file_label, language="python", nodes=visitor.nodes,
                   imports=visitor.imports, parser="python-ast", line_count=len(lines))


# ---------------------------------------------------------------------------
# Generic regex fallback
# ---------------------------------------------------------------------------
_FUNC_PATTERNS = [
    re.compile(r"^\s*(?:public|private|protected|static|final|async|export|pub|fn|def|function|\s)*"
               r"\b(?:def|fn|function)\s+([A-Za-z_]\w*)\s*\("),
    re.compile(r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?"
               r"[\w<>\[\].]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws [\w, .]+)?\s*\{"),
]
_CLASS_PATTERN = re.compile(r"^\s*(?:public|private|export|pub|abstract|final|\s)*"
                            r"\b(?:class|struct|interface|trait|enum)\s+([A-Za-z_]\w*)")
_IMPORT_PATTERN = re.compile(
    r"^\s*(?:import\s+(?:.*?\bfrom\s+)?['\"]?([\w./@\-]+)|"
    r"from\s+([\w.]+)\s+import|use\s+([\w:]+)|#include\s*[<\"]([\w./]+))")
_CALL_PATTERN = re.compile(r"\b([A-Za-z_][\w.]*(?:::[A-Za-z_]\w*)*)\s*\(")
_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "match", "with",
             "elif", "else", "do", "fn", "def", "function", "class", "new", "await",
             "print", "assert", "throw", "yield", "in", "and", "or", "not"}


def regex_ust(source: str, file_label: str, language: str) -> USTFile:
    """Best-effort UST for a language with no grammar and no stdlib parser."""
    lines = source.splitlines()
    nodes: list[USTNode] = []
    imports: list[str] = []
    current_fn = ""
    current_cls = ""

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*", "--")):
            continue

        span = SourceSpan(start_line=lineno, start_column=len(line) - len(line.lstrip()),
                          end_line=lineno, end_column=len(line))

        m = _IMPORT_PATTERN.match(line)
        if m:
            target = next((g for g in m.groups() if g), "")
            if target:
                imports.append(target)
                nodes.append(USTNode(type=USTNodeType.IMPORT, language=language,
                                     file=file_label, span=span, name=target,
                                     symbol=target, snippet=stripped[:MAX_SNIPPET],
                                     metadata={"grammar_type": "regex_import"}))
            continue

        # A declaration and a call can share a line — `class A { void f() {
        # Cipher.getInstance("RSA"); } }` is one line of perfectly ordinary
        # Java. Record the declaration and keep scanning the same line for
        # calls rather than moving on, which silently lost every finding in
        # brace-heavy or minified code.
        declaration_end = 0

        m = _CLASS_PATTERN.match(line)
        if m:
            current_cls = m.group(1)
            current_fn = ""
            declaration_end = m.end()
            nodes.append(USTNode(type=USTNodeType.CLASS, language=language,
                                 file=file_label, span=span, name=current_cls,
                                 symbol=current_cls, snippet=stripped[:MAX_SNIPPET],
                                 metadata={"grammar_type": "regex_class"}))

        for pat in _FUNC_PATTERNS:
            m = pat.match(line)
            if m:
                current_fn = m.group(1)
                declaration_end = max(declaration_end, m.end())
                nodes.append(USTNode(
                    type=USTNodeType.FUNCTION, language=language, file=file_label,
                    span=span, name=current_fn,
                    symbol=f"{current_cls}.{current_fn}" if current_cls else current_fn,
                    enclosing_class=current_cls, snippet=stripped[:MAX_SNIPPET],
                    metadata={"grammar_type": "regex_function"}))
                break

        for m in _CALL_PATTERN.finditer(line, declaration_end):
            symbol = m.group(1).replace("::", ".")
            if symbol.split(".")[-1] in _KEYWORDS or symbol in _KEYWORDS:
                continue
            args_text = line[m.end():]
            literals = re.findall(r'["\']([^"\']{1,120})["\']', args_text)
            nodes.append(USTNode(
                type=USTNodeType.CALL, language=language, file=file_label, span=span,
                name=symbol.rsplit(".", 1)[-1], symbol=symbol,
                arguments=[args_text.split(")")[0][:160]] if args_text else [],
                literals=literals[:6],
                enclosing_function=current_fn, enclosing_class=current_cls,
                snippet=stripped[:MAX_SNIPPET],
                metadata={"grammar_type": "regex_call"}))

    return USTFile(path=file_label, language=language, nodes=nodes, imports=imports,
                   parser="regex", line_count=len(lines))
