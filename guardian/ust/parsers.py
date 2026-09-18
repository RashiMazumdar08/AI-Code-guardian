"""
Tree-sitter Parser Registry
===========================
Owns every interaction with the `tree_sitter` bindings so the rest of
the platform never imports them directly. Responsibilities:

  * map file extension -> language key (python/java/javascript/typescript/rust)
  * lazily load and cache one `Parser` per language
  * degrade gracefully: if `tree_sitter` or a grammar package is missing,
    `parser_for()` returns None and the UST builder falls back to the
    stdlib-AST / regex path instead of failing the scan.

Adding a language later = add one row to `_GRAMMARS` plus a normalizer
module in `guardian/ust/languages/`. Nothing else changes.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

#: extension -> canonical language key
EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".rs": "rust",
}

#: language key -> (pypi module, factory attribute)
#: `tsx` and `typescript` share one grammar package with two entry points.
_GRAMMARS: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
    "java": ("tree_sitter_java", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "rust": ("tree_sitter_rust", "language"),
}

#: languages whose UST normalizer treats them identically
LANGUAGE_ALIASES = {"tsx": "typescript"}

_parser_cache: dict[str, Any] = {}
_unavailable: set[str] = set()


def language_for_path(path: str | Path) -> str:
    """Canonical language key for a path, or "" when unsupported."""
    return EXTENSION_LANGUAGE.get(Path(str(path)).suffix.lower(), "")


def normalizer_language(language: str) -> str:
    """Collapse grammar variants onto the normalizer that handles them."""
    return LANGUAGE_ALIASES.get(language, language)


def supported_languages() -> list[str]:
    return sorted(_GRAMMARS)


def supported_extensions() -> set[str]:
    return set(EXTENSION_LANGUAGE)


def tree_sitter_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        return True
    except ImportError:
        return False


def parser_for(language: str) -> Optional[Any]:
    """Return a cached `tree_sitter.Parser` for `language`, or None.

    None is a normal, expected outcome (grammar not installed) — callers
    fall back rather than fail. Failures are logged once per language.
    """
    if not language or language in _unavailable:
        return None
    cached = _parser_cache.get(language)
    if cached is not None:
        return cached

    spec = _GRAMMARS.get(language)
    if spec is None:
        _unavailable.add(language)
        return None

    module_name, attr = spec
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        if "tree_sitter" not in _unavailable:
            log.info("tree_sitter not installed; UST falls back to AST/regex parsing")
            _unavailable.add("tree_sitter")
        _unavailable.add(language)
        return None

    try:
        grammar_module = __import__(module_name)
        factory = getattr(grammar_module, attr)
        ts_language = Language(factory())
        parser = Parser(ts_language)
    except Exception as exc:  # noqa: BLE001 — any grammar problem must degrade, not crash
        log.info("tree-sitter grammar for %s unavailable (%s); using fallback", language, exc)
        _unavailable.add(language)
        return None

    _parser_cache[language] = parser
    return parser


def parse(source: str, language: str) -> Optional[Any]:
    """Parse source into a tree-sitter Tree, or None when unavailable.

    Tree-sitter is error-tolerant: a syntactically broken file still
    yields a usable tree with ERROR nodes, which is exactly the partial
    coverage we want on malformed input.
    """
    parser = parser_for(language)
    if parser is None:
        return None
    try:
        return parser.parse(source.encode("utf-8", errors="ignore"))
    except Exception as exc:  # noqa: BLE001
        log.debug("tree-sitter parse failed for %s: %s", language, exc)
        return None


def availability() -> dict[str, bool]:
    """Diagnostic map used by the CLI/dashboard to show parser coverage."""
    return {lang: parser_for(lang) is not None for lang in supported_languages()}
