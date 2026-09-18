"""
AI Code Guardian 2.0 — Plugin Registry
======================================
Central, configuration-driven registry for every extension point.
Plugins self-register at import time via the decorators below; the
pipeline then asks the registry "who handles .java?" instead of
hardcoding any language or analyzer anywhere.

Adding a new language = drop a module in guardian/scanner/<lang>/ that
calls @register_language. Nothing else in the platform changes.
"""
from __future__ import annotations

import logging
from typing import Optional

from guardian.core.interfaces import Analyzer, LanguagePlugin, Reporter

log = logging.getLogger(__name__)


class Registry:
    def __init__(self) -> None:
        self._languages: dict[str, LanguagePlugin] = {}
        self._by_extension: dict[str, LanguagePlugin] = {}
        self._analyzers: dict[str, Analyzer] = {}
        self._reporters: dict[str, Reporter] = {}

    # -- languages -----------------------------------------------------
    def register_language(self, plugin: LanguagePlugin) -> None:
        self._languages[plugin.name] = plugin
        for ext in plugin.extensions:
            self._by_extension[ext.lower()] = plugin
        log.debug("registered language plugin %s (%s)", plugin.name, plugin.extensions)

    def language_for(self, path_or_ext: str) -> Optional[LanguagePlugin]:
        ext = path_or_ext if path_or_ext.startswith(".") else "." + path_or_ext.rsplit(".", 1)[-1]
        return self._by_extension.get(ext.lower())

    @property
    def languages(self) -> dict[str, LanguagePlugin]:
        return dict(self._languages)

    @property
    def supported_extensions(self) -> set[str]:
        return set(self._by_extension)

    # -- analyzers -----------------------------------------------------
    def register_analyzer(self, analyzer: Analyzer) -> None:
        self._analyzers[analyzer.name] = analyzer

    @property
    def analyzers(self) -> dict[str, Analyzer]:
        return dict(self._analyzers)

    # -- reporters -----------------------------------------------------
    def register_reporter(self, reporter: Reporter) -> None:
        self._reporters[reporter.name] = reporter

    def reporter(self, name: str) -> Optional[Reporter]:
        return self._reporters.get(name)

    @property
    def reporters(self) -> dict[str, Reporter]:
        return dict(self._reporters)


#: Process-wide default registry. The pipeline accepts an explicit
#: Registry for tests; production code uses this one.
default_registry = Registry()


def register_language(cls):
    """Class decorator: instantiate and register a LanguagePlugin."""
    default_registry.register_language(cls())
    return cls


def register_analyzer(cls):
    default_registry.register_analyzer(cls())
    return cls


def register_reporter(cls):
    default_registry.register_reporter(cls())
    return cls


def load_builtin_plugins() -> Registry:
    """Import every built-in plugin package so decorators fire.
    Idempotent — safe to call multiple times."""
    from guardian.scanner import java, python, javascript, rust  # noqa: F401
    from guardian import dependencies, infrastructure      # noqa: F401
    from guardian.quantum import plugin as _qp             # noqa: F401
    from guardian.reporting import json_reporter, sarif, html_reporter, csv_reporter, pdf_reporter  # noqa: F401
    # Optional third-party scanner adapters -- both off by default
    # (ENABLE_SEMGREP / ENABLE_SNYK), both degrade to zero findings rather
    # than failing the scan when their tool/credentials aren't present.
    # Importing them here (so @register_analyzer fires) is the only wiring
    # guardian/core/pipeline.py needs -- it already iterates every
    # registered Analyzer.
    from guardian.scanner import semgrep_adapter as _semgrep  # noqa: F401
    from guardian.dependencies import snyk_adapter as _snyk   # noqa: F401
    return default_registry
