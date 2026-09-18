"""
UST Normalizer — Language-Independent Base
==========================================
One table-driven walk turns a Tree-sitter parse tree into `USTNode`s.

Each language subclass supplies only *vocabulary*: which grammar node
types mean "function", "call", "import", and so on, plus overrides for
the handful of places where grammars genuinely differ (Java splits a
method call into `object` + `name`; Python/JS/Rust expose the whole
callee under a single `function` field).

Everything structural — scope tracking, span extraction, argument and
literal extraction, snippet bounding — lives here once.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from guardian.ust.models import SourceSpan, USTNode, USTNodeType

log = logging.getLogger(__name__)

MAX_SNIPPET = 240
MAX_ARG_TEXT = 160
MAX_ARGS = 12
MAX_NODES_PER_FILE = 20_000   # safety valve for machine-generated files

_QUOTES = "\"'`"


class LanguageNormalizer:
    """Base class. Subclasses set the vocabulary sets below."""

    language: str = "unknown"

    FUNCTION_TYPES: set[str] = set()
    CLASS_TYPES: set[str] = set()
    CALL_TYPES: set[str] = set()
    OBJECT_CREATION_TYPES: set[str] = set()
    IMPORT_TYPES: set[str] = set()
    ASSIGNMENT_TYPES: set[str] = set()
    PARAMETER_TYPES: set[str] = set()
    CONDITIONAL_TYPES: set[str] = set()
    LOOP_TYPES: set[str] = set()
    RETURN_TYPES: set[str] = set()
    EXCEPTION_TYPES: set[str] = set()
    ANNOTATION_TYPES: set[str] = set()
    STRING_TYPES: set[str] = {"string", "string_literal", "template_string",
                              "raw_string_literal", "interpreted_string_literal"}

    #: grammar field holding a callee expression (single-field grammars)
    CALLEE_FIELD = "function"
    #: grammar field holding the argument list
    ARGS_FIELD = "arguments"
    #: grammar field holding a declaration's name
    NAME_FIELD = "name"
    #: grammar field holding a function/class body
    BODY_FIELD = "body"
    #: grammar field holding a parameter list
    PARAMS_FIELD = "parameters"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def normalize(self, tree: Any, source: str, file_label: str) -> tuple[list[USTNode], list[str]]:
        """Walk `tree` and return (nodes, imports)."""
        self._source_bytes = source.encode("utf-8", errors="ignore")
        nodes: list[USTNode] = []
        imports: list[str] = []

        root = getattr(tree, "root_node", tree)
        # stack entries: (ts_node, enclosing_function, enclosing_class, parent_id, depth_flags)
        stack: list[tuple[Any, str, str, str, dict]] = [(root, "", "", "", {})]

        while stack:
            node, fn_scope, cls_scope, parent_id, flags = stack.pop()
            if len(nodes) >= MAX_NODES_PER_FILE:
                break

            ust_node: Optional[USTNode] = None
            child_fn, child_cls = fn_scope, cls_scope
            child_flags = flags

            if node.is_named:
                kind = self._ust_type(node.type)
                if kind is not None:
                    ust_node = self._build(node, kind, file_label, fn_scope, cls_scope,
                                           parent_id, flags)
                    if ust_node is not None:
                        nodes.append(ust_node)
                        if kind is USTNodeType.IMPORT and ust_node.name:
                            imports.append(ust_node.name)
                        if kind is USTNodeType.FUNCTION:
                            child_fn = ust_node.name or fn_scope
                        elif kind is USTNodeType.CLASS:
                            child_cls = ust_node.name or cls_scope
                        if kind is USTNodeType.CONDITIONAL:
                            child_flags = {**flags, "in_conditional": True}
                        elif kind is USTNodeType.LOOP:
                            child_flags = {**flags, "in_loop": True}
                        elif kind is USTNodeType.EXCEPTION_HANDLING:
                            child_flags = {**flags, "in_exception_handler": True}

            new_parent = ust_node.node_id if ust_node is not None else parent_id
            for child in reversed(node.children):
                stack.append((child, child_fn, child_cls, new_parent, child_flags))

        nodes.sort(key=lambda n: (n.span.start_line, n.span.start_column))
        return nodes, imports

    # ------------------------------------------------------------------
    # Type mapping
    # ------------------------------------------------------------------
    def _ust_type(self, grammar_type: str) -> Optional[USTNodeType]:
        if grammar_type in self.FUNCTION_TYPES:
            return USTNodeType.FUNCTION
        if grammar_type in self.CLASS_TYPES:
            return USTNodeType.CLASS
        if grammar_type in self.OBJECT_CREATION_TYPES:
            return USTNodeType.OBJECT_CREATION
        if grammar_type in self.CALL_TYPES:
            return USTNodeType.CALL
        if grammar_type in self.IMPORT_TYPES:
            return USTNodeType.IMPORT
        if grammar_type in self.ASSIGNMENT_TYPES:
            return USTNodeType.ASSIGNMENT
        if grammar_type in self.PARAMETER_TYPES:
            return USTNodeType.PARAMETER
        if grammar_type in self.CONDITIONAL_TYPES:
            return USTNodeType.CONDITIONAL
        if grammar_type in self.LOOP_TYPES:
            return USTNodeType.LOOP
        if grammar_type in self.RETURN_TYPES:
            return USTNodeType.RETURN
        if grammar_type in self.EXCEPTION_TYPES:
            return USTNodeType.EXCEPTION_HANDLING
        if grammar_type in self.ANNOTATION_TYPES:
            return USTNodeType.ANNOTATION
        return None

    # ------------------------------------------------------------------
    # Node construction
    # ------------------------------------------------------------------
    def _build(self, node: Any, kind: USTNodeType, file_label: str,
               fn_scope: str, cls_scope: str, parent_id: str,
               flags: dict) -> Optional[USTNode]:
        span = self._span(node)
        name, symbol = "", ""
        arguments: list[str] = []
        literals: list[str] = []
        parameters: list[str] = []

        if kind in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION):
            symbol = self.callee_symbol(node)
            name = symbol.rsplit(".", 1)[-1] if symbol else ""
            arguments = self.call_arguments(node)
            literals = [self._unquote(a) for a in arguments if self._is_literal_text(a)]
            if not symbol:
                return None
        elif kind is USTNodeType.FUNCTION:
            name = self.declaration_name(node)
            symbol = f"{cls_scope}.{name}" if cls_scope and name else name
            parameters = self.parameter_names(node)
        elif kind is USTNodeType.CLASS:
            name = self.declaration_name(node)
            symbol = name
        elif kind is USTNodeType.IMPORT:
            name = self.import_target(node)
            symbol = name
        elif kind is USTNodeType.ASSIGNMENT:
            name = self.assignment_target(node)
            symbol = name
            value = self.assignment_value(node)
            if value:
                arguments = [value[:MAX_ARG_TEXT]]
                if self._is_literal_text(value):
                    literals = [self._unquote(value)]
        elif kind is USTNodeType.PARAMETER:
            name = self._text(node).strip()
            symbol = name
        elif kind is USTNodeType.ANNOTATION:
            name = self.annotation_name(node)
            symbol = name
            arguments = self.call_arguments(node)
        else:
            name = ""

        return USTNode(
            type=kind,
            language=self.language,
            file=file_label,
            span=span,
            name=name,
            symbol=symbol,
            snippet=self._snippet(node),
            arguments=arguments[:MAX_ARGS],
            literals=[lit for lit in literals if lit][:MAX_ARGS],
            parameters=parameters[:MAX_ARGS],
            enclosing_function=fn_scope,
            enclosing_class=cls_scope,
            parent_id=parent_id,
            control_flow={k: v for k, v in flags.items() if v},
            metadata={"grammar_type": node.type},
        )

    # ------------------------------------------------------------------
    # Language hooks — overridable
    # ------------------------------------------------------------------
    def callee_symbol(self, node: Any) -> str:
        """Dotted callee name, e.g. `Cipher.getInstance` or `hashlib.md5`."""
        for field in (self.CALLEE_FIELD, "constructor", "type"):
            child = self._field(node, field)
            if child is not None:
                return self._normalise_symbol(self._text(child))
        return ""

    def call_arguments(self, node: Any) -> list[str]:
        args_node = self._field(node, self.ARGS_FIELD)
        if args_node is None:
            args_node = next((c for c in node.children
                              if c.type in ("argument_list", "arguments")), None)
        if args_node is None:
            return []
        out: list[str] = []
        for child in args_node.children:
            if not child.is_named:
                continue
            out.append(self._text(child).strip()[:MAX_ARG_TEXT])
        return out

    def declaration_name(self, node: Any) -> str:
        child = self._field(node, self.NAME_FIELD)
        return self._text(child).strip() if child is not None else ""

    def parameter_names(self, node: Any) -> list[str]:
        params = self._field(node, self.PARAMS_FIELD)
        if params is None:
            return []
        out: list[str] = []
        for child in params.children:
            if not child.is_named:
                continue
            named = self._field(child, self.NAME_FIELD)
            text = self._text(named if named is not None else child).strip()
            if text:
                out.append(text)
        return out

    def import_target(self, node: Any) -> str:
        child = self._field(node, self.NAME_FIELD) or self._field(node, "source") \
            or self._field(node, "module_name") or self._field(node, "argument")
        if child is not None:
            return self._unquote(self._text(child).strip())
        return self._text(node).strip().rstrip(";")

    def assignment_target(self, node: Any) -> str:
        child = self._field(node, "left") or self._field(node, self.NAME_FIELD) \
            or self._field(node, "pattern")
        return self._text(child).strip() if child is not None else ""

    def assignment_value(self, node: Any) -> str:
        child = self._field(node, "right") or self._field(node, "value")
        return self._text(child).strip() if child is not None else ""

    def annotation_name(self, node: Any) -> str:
        child = self._field(node, self.NAME_FIELD)
        if child is not None:
            return self._text(child).strip()
        text = self._text(node).strip().lstrip("@#[]!")
        return text.split("(")[0].strip()[:80]

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------
    @staticmethod
    def _field(node: Any, field: str) -> Optional[Any]:
        try:
            return node.child_by_field_name(field)
        except Exception:  # noqa: BLE001 — grammar without that field
            return None

    def _text(self, node: Any) -> str:
        if node is None:
            return ""
        try:
            return self._source_bytes[node.start_byte:node.end_byte].decode(
                "utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return ""

    def _snippet(self, node: Any) -> str:
        text = self._text(node)
        first_line = text.split("\n", 1)[0].strip()
        return first_line[:MAX_SNIPPET]

    @staticmethod
    def _span(node: Any) -> SourceSpan:
        start_row, start_col = node.start_point
        end_row, end_col = node.end_point
        return SourceSpan(start_line=start_row + 1, start_column=start_col,
                          end_line=end_row + 1, end_column=end_col)

    @staticmethod
    def _normalise_symbol(text: str) -> str:
        """Collapse a callee expression into a dotted symbol.

        Grammars hand back things like `hashlib.md5(data).hexdigest`,
        `self.repo.query` or `foo[0].bar`. Keeping only identifier/`.`
        characters gives detectors a predictable token without each of
        them re-inventing the cleanup.

        Nested call arguments are skipped rather than terminating the
        scan, so a chained call keeps its full path
        (`hashlib.md5.hexdigest`). Truncating at the first `(` would make
        the outer node indistinguishable from the inner `hashlib.md5`
        one, and every detector matching on the symbol would fire twice
        for a single crypto operation.
        """
        text = text.strip().replace("::", ".").replace("->", ".")
        cleaned: list[str] = []
        depth = 0
        for ch in text:
            if depth:
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                continue
            if ch.isalnum() or ch in "._$":
                cleaned.append(ch)
            elif ch in "([{":
                depth += 1
                # a call/index in the middle of the chain ends this segment
                cleaned.append(".")
            elif ch in " \t\n":
                continue
            else:
                cleaned.append(".")
        symbol = "".join(cleaned).strip(".")
        while ".." in symbol:
            symbol = symbol.replace("..", ".")
        return symbol[:200]

    @staticmethod
    def _is_literal_text(text: str) -> bool:
        text = text.strip()
        return len(text) >= 2 and text[0] in _QUOTES and text[-1] == text[0]

    @staticmethod
    def _unquote(text: str) -> str:
        text = text.strip()
        if len(text) >= 2 and text[0] in _QUOTES and text[-1] == text[0]:
            return text[1:-1]
        return text


def collect_identifiers(text: str) -> set[str]:
    """Identifier-ish tokens in an expression — used by the data-flow pass."""
    out: set[str] = set()
    token: list[str] = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            token.append(ch)
        else:
            if token:
                out.add("".join(token))
                token = []
    if token:
        out.add("".join(token))
    return out


def merge_normalizers(*groups: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for g in groups:
        out |= set(g)
    return out
