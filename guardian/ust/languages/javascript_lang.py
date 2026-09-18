"""JavaScript / TypeScript / TSX UST normalizer.

One normalizer covers all three: the TypeScript and TSX grammars are
supersets of JavaScript, and every vocabulary token used here exists in
all of them. `language` is set per instance so USTNodes report the real
source language rather than a lowest common denominator.
"""
from __future__ import annotations

from typing import Any

from guardian.ust.languages.base import LanguageNormalizer


class JavaScriptNormalizer(LanguageNormalizer):
    language = "javascript"

    FUNCTION_TYPES = {"function_declaration", "function_expression", "function",
                      "arrow_function", "method_definition", "generator_function_declaration"}
    CLASS_TYPES = {"class_declaration", "class"}
    CALL_TYPES = {"call_expression"}
    OBJECT_CREATION_TYPES = {"new_expression"}
    IMPORT_TYPES = {"import_statement"}
    ASSIGNMENT_TYPES = {"variable_declarator", "assignment_expression",
                        "augmented_assignment_expression"}
    PARAMETER_TYPES: set[str] = set()
    CONDITIONAL_TYPES = {"if_statement", "switch_statement", "ternary_expression"}
    LOOP_TYPES = {"for_statement", "for_in_statement", "while_statement", "do_statement"}
    RETURN_TYPES = {"return_statement"}
    EXCEPTION_TYPES = {"try_statement", "catch_clause", "throw_statement"}
    ANNOTATION_TYPES = {"decorator"}

    def __init__(self, language: str = "javascript") -> None:
        self.language = language

    def declaration_name(self, node: Any) -> str:
        name = super().declaration_name(node)
        if name:
            return name
        # `const handler = () => {}` / `foo: function () {}` — arrow and
        # anonymous functions take the name of the binding they're assigned to.
        parent = getattr(node, "parent", None)
        while parent is not None and parent.type in ("parenthesized_expression",):
            parent = getattr(parent, "parent", None)
        if parent is not None and parent.type in (
                "variable_declarator", "assignment_expression", "pair", "public_field_definition"):
            target = (self._field(parent, "name") or self._field(parent, "left")
                      or self._field(parent, "key"))
            if target is not None:
                return self._text(target).strip()
        return ""

    def import_target(self, node: Any) -> str:
        source = self._field(node, "source")
        if source is not None:
            return self._unquote(self._text(source).strip())
        return self._text(node).strip().rstrip(";")

    def assignment_value(self, node: Any) -> str:
        child = self._field(node, "value") or self._field(node, "right")
        return self._text(child).strip() if child is not None else ""


class TypeScriptNormalizer(JavaScriptNormalizer):
    """TypeScript adds decorators, parameter properties and type annotations."""

    def __init__(self, language: str = "typescript") -> None:
        super().__init__(language)

    def parameter_names(self, node: Any) -> list[str]:
        params = self._field(node, self.PARAMS_FIELD)
        if params is None:
            return []
        out: list[str] = []
        for child in params.children:
            if not child.is_named:
                continue
            # required_parameter / optional_parameter wrap the real pattern
            pattern = self._field(child, "pattern") or self._field(child, "name")
            text = self._text(pattern if pattern is not None else child).strip()
            if text:
                out.append(text)
        return out
