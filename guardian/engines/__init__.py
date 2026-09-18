"""
Analysis engines
================
Each engine implements `analyze(AnalysisContext) -> EngineResult` and
publishes Evidence into the shared store. Engines never call each other
and never talk to an LLM directly — contextual reasoning happens later,
over selected evidence, in `guardian.reasoning`.
"""
from guardian.engines.base import (  # noqa: F401
    AnalysisEngine, BaseEngine, EngineResult, run_engine,
)

__all__ = ["AnalysisEngine", "BaseEngine", "EngineResult", "run_engine"]
