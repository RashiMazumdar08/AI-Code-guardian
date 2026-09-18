"""Rust UST normalizer (Tree-sitter grammar vocabulary)."""
from __future__ import annotations

from typing import Any

from guardian.ust.languages.base import LanguageNormalizer


class RustNormalizer(LanguageNormalizer):
    language = "rust"

    FUNCTION_TYPES = {"function_item", "closure_expression"}
    CLASS_TYPES = {"struct_item", "impl_item", "trait_item", "enum_item"}
    CALL_TYPES = {"call_expression", "macro_invocation"}
    OBJECT_CREATION_TYPES = {"struct_expression"}
    IMPORT_TYPES = {"use_declaration", "extern_crate_declaration"}
    ASSIGNMENT_TYPES = {"let_declaration", "assignment_expression",
                        "compound_assignment_expr"}
    PARAMETER_TYPES: set[str] = set()
    CONDITIONAL_TYPES = {"if_expression", "match_expression", "if_let_expression"}
    LOOP_TYPES = {"for_expression", "while_expression", "loop_expression"}
    RETURN_TYPES = {"return_expression"}
    EXCEPTION_TYPES = {"try_expression"}
    ANNOTATION_TYPES = {"attribute_item", "inner_attribute_item"}

    def callee_symbol(self, node: Any) -> str:
        if node.type == "macro_invocation":
            macro = self._field(node, "macro")
            name = self._normalise_symbol(self._text(macro)) if macro is not None else ""
            return f"{name}!" if name else ""
        if node.type == "struct_expression":
            body = self._field(node, "name")
            return self._normalise_symbol(self._text(body)) if body is not None else ""
        return super().callee_symbol(node)

    def call_arguments(self, node: Any) -> list[str]:
        if node.type == "macro_invocation":
            # macro token trees are unstructured; split the top level on commas
            tokens = next((c for c in node.children if c.type == "token_tree"), None)
            if tokens is None:
                return []
            inner = self._text(tokens).strip()
            if inner.startswith(("(", "[", "{")):
                inner = inner[1:-1] if len(inner) >= 2 else ""
            return [part.strip()[:160] for part in _split_top_level(inner) if part.strip()][:12]
        return super().call_arguments(node)

    def import_target(self, node: Any) -> str:
        arg = self._field(node, "argument")
        if arg is not None:
            return self._text(arg).strip().replace("::", ".")
        return self._text(node).strip().removeprefix("use").strip().rstrip(";").replace("::", ".")

    def assignment_target(self, node: Any) -> str:
        pattern = self._field(node, "pattern") or self._field(node, "left")
        return self._text(pattern).strip() if pattern is not None else ""

    def assignment_value(self, node: Any) -> str:
        child = self._field(node, "value") or self._field(node, "right")
        return self._text(child).strip() if child is not None else ""

    def annotation_name(self, node: Any) -> str:
        text = self._text(node).strip()
        for prefix in ("#![", "#["):
            if text.startswith(prefix):
                text = text[len(prefix):].rstrip("]")
                break
        return text.split("(")[0].strip()[:80]


def _split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside brackets or strings."""
    parts: list[str] = []
    depth = 0
    in_str = False
    quote = ""
    current: list[str] = []
    escaped = False
    for ch in text:
        if in_str:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_str = False
            continue
        if ch in "\"'":
            in_str, quote = True, ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts
