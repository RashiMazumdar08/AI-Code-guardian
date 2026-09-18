"""
Threat Intelligence Engine
============================
Public API surface.

    from guardian.threat_intel import ThreatIntelligenceEngine

    engine = ThreatIntelligenceEngine()
    ctx = engine.lookup("log4j-core", "2.14.1")
    ctx = engine.lookup("spring-core", "5.3.18")
"""
from guardian.threat_intel.models import (
    CVERecord, ThreatContext, FeedMetadata, FeedSource
)
from guardian.threat_intel.collector import (
    ThreatIntelligenceCollector, NVDCollector, CISAKEVCollector, OSVCollector
)
from guardian.threat_intel.normalizer import CVENormalizer
from guardian.threat_intel.cache import ThreatIntelCache
from guardian.threat_intel.retriever import ThreatIntelRetriever
from typing import Optional


class ThreatIntelligenceEngine:
    """
    Top-level facade. Use this in Risk Scorer and Dashboard.
    Supports dependency injection for all sub-components.
    """

    def __init__(
        self,
        retriever: Optional[ThreatIntelRetriever] = None,
    ):
        self._retriever = retriever or ThreatIntelRetriever()

    def lookup(self, package: str, version: Optional[str] = None) -> ThreatContext:
        return self._retriever.lookup(package, version)

    def lookup_many(self, packages: list[tuple[str, Optional[str]]]) -> list[ThreatContext]:
        return self._retriever.lookup_many(packages)

    def feed_health(self) -> dict[str, bool]:
        return self._retriever._collector.health()
