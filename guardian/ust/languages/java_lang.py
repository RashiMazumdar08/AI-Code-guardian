"""Java UST normalizer (Tree-sitter grammar vocabulary)."""
from __future__ import annotations

from typing import Any

from guardian.ust.languages.base import LanguageNormalizer


class JavaNormalizer(LanguageNormalizer):
    language = "java"

    FUNCTION_TYPES = {"method_declaration", "constructor_declaration"}
    CLASS_TYPES = {"class_declaration", "interface_declaration",
                   "enum_declaration", "record_declaration"}
    CALL_TYPES = {"method_invocation"}
    OBJECT_CREATION_TYPES = {"object_creation_expression"}
    IMPORT_TYPES = {"import_declaration"}
    ASSIGNMENT_TYPES = {"variable_declarator", "assignment_expression"}
    PARAMETER_TYPES: set[str] = set()
    CONDITIONAL_TYPES = {"if_statement", "switch_expression", "ternary_expression"}
    LOOP_TYPES = {"for_statement", "enhanced_for_statement", "while_statement", "do_statement"}
    RETURN_TYPES = {"return_statement"}
    EXCEPTION_TYPES = {"try_statement", "catch_clause", "throw_statement"}
    ANNOTATION_TYPES = {"annotation", "marker_annotation"}

    def callee_symbol(self, node: Any) -> str:
        """Java splits a call into `object` + `name`; rebuild the dotted form.

        `Cipher.getInstance("RSA")` -> "Cipher.getInstance"
        `c.doFinal(x)`              -> "c.doFinal"
        `new Foo(1)`                -> "Foo"
        """
        if node.type == "object_creation_expression":
            type_node = self._field(node, "type")
            return self._normalise_symbol(self._text(type_node)) if type_node is not None else ""
        name = self._field(node, "name")
        obj = self._field(node, "object")
        name_text = self._text(name).strip() if name is not None else ""
        obj_text = self._normalise_symbol(self._text(obj)) if obj is not None else ""
        if obj_text and name_text:
            return f"{obj_text}.{name_text}"[:200]
        return name_text or obj_text

    def import_target(self, node: Any) -> str:
        text = self._text(node).strip()
        return text.removeprefix("import").strip().removeprefix("static").strip().rstrip(";")

    def assignment_value(self, node: Any) -> str:
        child = self._field(node, "value") or self._field(node, "right")
        return self._text(child).strip() if child is not None else ""
