"""
Shared Analysis Contexts
========================
`RepositoryContext` — everything known about the repository *before*
analysis: where it is, what files it has, what it is written in.

`AnalysisContext` — the mutable working set every engine receives and
contributes to: the UST, the evidence store, deterministic findings, and
per-engine outputs. Engines exchange these objects instead of each
inventing its own incompatible result shape.

Both are deliberately plain containers. Orchestration lives in
`guardian.core.pipeline`; knowledge lives in the engines.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from guardian.config import GuardianConfig
from guardian.core.models import Finding
from guardian.evidence.store import EvidenceStore
from guardian.ust.models import UST


@dataclass
class RepositoryContext:
    """Immutable-ish description of the scan target."""

    root: Path
    source_files: list[Path] = field(default_factory=list)
    manifest_files: list[Path] = field(default_factory=list)
    infrastructure_files: list[Path] = field(default_factory=list)
    doc_files: list[Path] = field(default_factory=list)
    other_files: list[Path] = field(default_factory=list)

    profile: Any = None                      # discovery.repo_detector.RepositoryProfile
    truncated: bool = False

    @property
    def all_files(self) -> list[Path]:
        return (self.source_files + self.manifest_files + self.infrastructure_files
                + self.doc_files + self.other_files)

    def relative(self, path: Path | str) -> str:
        """Repo-relative label used consistently in every Finding/Evidence."""
        p = Path(path)
        try:
            return str(p.resolve().relative_to(Path(self.root).resolve()))
        except (ValueError, OSError):
            try:
                return str(p.relative_to(self.root))
            except ValueError:
                return str(p)

    def read(self, path: Path | str) -> str:
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    @property
    def primary_language(self) -> str:
        return getattr(self.profile, "primary_language", "Unknown")

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "source_files": len(self.source_files),
            "manifest_files": len(self.manifest_files),
            "infrastructure_files": len(self.infrastructure_files),
            "doc_files": len(self.doc_files),
            "truncated": self.truncated,
        }


@dataclass
class AnalysisContext:
    """The working set threaded through every engine in the pipeline."""

    repository: RepositoryContext
    config: GuardianConfig = field(default_factory=GuardianConfig)
    ust: UST = field(default_factory=UST)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    findings: list[Finding] = field(default_factory=list)

    # per-engine structured output (quantum CBOM, business intent report, ...)
    engine_outputs: dict[str, Any] = field(default_factory=dict)
    # non-fatal failures; a scan returns partial results rather than crashing
    errors: list[dict] = field(default_factory=list)

    # optional inputs supplied by the caller
    business_requirements: list[Path] = field(default_factory=list)
    policy_path: Optional[Path] = None

    # -- mutation helpers ------------------------------------------------
    def add_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def record_error(self, stage: str, error: Exception | str) -> None:
        self.errors.append({"stage": stage, "error": str(error)})

    def set_output(self, engine: str, value: Any) -> None:
        self.engine_outputs[engine] = value

    def output(self, engine: str, default: Any = None) -> Any:
        return self.engine_outputs.get(engine, default)

    # -- lookups used by validation --------------------------------------
    def ust_file(self, path: str):
        return self.ust.files.get(path)

    def known_files(self) -> set[str]:
        files = {self.repository.relative(p) for p in self.repository.all_files}
        files |= set(self.ust.files)
        return files

    def known_functions(self, file: str = "") -> set[str]:
        names: set[str] = set()
        for uf in self.ust:
            if file and uf.path != file:
                continue
            for fn in uf.functions():
                if fn.name:
                    names.add(fn.name)
        return names

    def to_dict(self) -> dict:
        return {
            "repository": self.repository.to_dict(),
            "ust": self.ust.summary(),
            "evidence": self.evidence.summary(),
            "findings": len(self.findings),
            "engines": sorted(self.engine_outputs),
            "errors": self.errors,
        }
