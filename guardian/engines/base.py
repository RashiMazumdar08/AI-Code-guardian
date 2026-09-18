"""
Analysis Engine Contract
========================
Every engine in the pipeline implements the same shape:

    engine.analyze(context) -> EngineResult(evidence, findings, output)

The engine reads what it needs from the `AnalysisContext` (UST, evidence
already published by earlier engines, repository files) and returns
*new* evidence and findings. The pipeline — not the engine — publishes
into the store and aggregates. That keeps engines independently testable
and makes ordering explicit.

Failure policy: `run_engine()` never propagates an exception. A broken
engine costs its own results, not the whole scan.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

from guardian.core.context import AnalysisContext
from guardian.core.models import Finding
from guardian.evidence.models import Evidence

log = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """What one engine produced."""

    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    output: Any = None                  # engine-specific structured report
    error: str = ""
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.error


@runtime_checkable
class AnalysisEngine(Protocol):
    """Common interface for deterministic and contextual engines."""

    name: str

    def analyze(self, context: AnalysisContext) -> EngineResult:
        ...


def run_engine(engine: AnalysisEngine, context: AnalysisContext) -> EngineResult:
    """Run one engine defensively and publish its evidence into the store.

    Evidence IDs are assigned here, on publication, and back-filled onto
    any finding the engine produced so findings always cite real IDs.
    """
    started = time.time()
    try:
        result = engine.analyze(context)
    except Exception as exc:  # noqa: BLE001 — one engine must never kill a scan
        log.error("engine %s failed: %s", engine.name, exc, exc_info=log.isEnabledFor(logging.DEBUG))
        context.record_error(engine.name, exc)
        return EngineResult(error=str(exc), duration_seconds=time.time() - started)

    # Publish evidence and remember fingerprint -> assigned ID. Engines may
    # cite either form: fingerprints are known at construction time, IDs only
    # after publication, and translating here means no engine has to care.
    published: dict[str, str] = {}
    for item in result.evidence:
        stored = context.evidence.add(item)
        published[item.fingerprint] = stored.id
        item.id = stored.id

    for finding in result.findings:
        if not finding.engine:
            finding.engine = engine.name
        finding.evidence_ids = list(dict.fromkeys(
            published.get(eid, eid) for eid in finding.evidence_ids if eid))

    if result.output is not None:
        context.set_output(engine.name, result.output)

    result.duration_seconds = round(time.time() - started, 3)
    return result


class BaseEngine:
    """Small convenience base — engines may subclass or just duck-type."""

    name: str = "engine"

    def analyze(self, context: AnalysisContext) -> EngineResult:  # pragma: no cover
        raise NotImplementedError

    @staticmethod
    def _rel(context: AnalysisContext, path) -> str:
        return context.repository.relative(path)

    @staticmethod
    def _first_id(evidence: list[Evidence]) -> Optional[str]:
        return evidence[0].id if evidence else None
