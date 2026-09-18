"""Python UST normalizer (Tree-sitter grammar vocabulary)."""
from __future__ import annotations

from typing import Any

from guardian.ust.languages.base import LanguageNormalizer


class PythonNormalizer(LanguageNormalizer):
    language = "python"

    FUNCTION_TYPES = {"function_definition"}
    CLASS_TYPES = {"class_definition"}
    CALL_TYPES = {"call"}
    OBJECT_CREATION_TYPES: set[str] = set()   # Python constructs via plain calls
    IMPORT_TYPES = {"import_statement", "import_from_statement"}
    ASSIGNMENT_TYPES = {"assignment", "augmented_assignment"}
    PARAMETER_TYPES: set[str] = set()          # captured via function parameters
    CONDITIONAL_TYPES = {"if_statement", "conditional_expression", "match_statement"}
    LOOP_TYPES = {"for_statement", "while_statement"}
    RETURN_TYPES = {"return_statement"}
    EXCEPTION_TYPES = {"try_statement", "except_clause", "raise_statement"}
    ANNOTATION_TYPES = {"decorator"}

    def import_target(self, node: Any) -> str:
        """`import a.b` -> "a.b"; `from x.y import z` -> "x.y.z"."""
        module = self._field(node, "module_name")
        name = self._field(node, "name")
        if module is not None and name is not None:
            return f"{self._text(module).strip()}.{self._text(name).strip()}"
        if name is not None:
            return self._text(name).strip()
        if module is not None:
            return self._text(module).strip()
        return self._text(node).strip()

    def annotation_name(self, node: Any) -> str:
        text = self._text(node).strip().lstrip("@")
        return text.split("(")[0].strip()[:80]
