"""
AI Code Guardian 2.0 — Core Interfaces
======================================
Every extension point in the platform is defined here as a Protocol.
Plugins depend on these contracts and on `guardian.core.models` ONLY —
never on each other and never on any specific repository's structure.

Extension points:
    LanguagePlugin   — per-language source scanning (scanner/<lang>/)
    Analyzer         — cross-cutting analyzers (dependencies, infra, quantum)
    Reporter         — output formats (JSON, SARIF, HTML, PDF)
    IntentClassifier — repository business-domain classification
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from guardian.core.models import Finding


@runtime_checkable
class LanguagePlugin(Protocol):
    """A language plugin owns a set of file extensions and knows how to
    produce Findings from source text in that language.

    Implementations MUST be stateless with respect to any particular
    repository (configuration-driven, no hardcoded project assumptions).
    """

    #: Unique plugin name, e.g. "java", "python".
    name: str
    #: File extensions this plugin claims, e.g. (".java",).
    extensions: tuple[str, ...]

    def scan_source(self, source: str, file_label: str) -> list[Finding]:
        """Scan a single file's source text. `file_label` is the
        repository-relative path used in Finding.file."""
        ...


@runtime_checkable
class Analyzer(Protocol):
    """A cross-cutting analyzer runs once per repository (not per file).
    Examples: dependency CVE analysis, IaC scanning, quantum inventory.
    """

    name: str

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        ...


@runtime_checkable
class Reporter(Protocol):
    """Serialises a completed scan into an output format."""

    name: str
    file_extension: str  # e.g. ".sarif"

    def render(self, report: dict) -> str:
        """`report` is the pipeline's aggregate dict (see pipeline.py)."""
        ...


@runtime_checkable
class IntentClassifier(Protocol):
    """Classifies a repository into a business domain with evidence."""

    def classify(self, repo_root: Path) -> "DomainVerdict":  # noqa: F821
        ...
