"""
Threat Intelligence Engine — Retriever
=========================================
High-level lookup API consumed by the Risk Scorer and Dashboard.

Usage:
    retriever = ThreatIntelRetriever()
    ctx = retriever.lookup("log4j-core", "2.14.1")
    print(ctx.max_cvss, ctx.known_exploited_count)

Caching: results are served from disk cache first; live fetch only on miss
or expiry. Pass `force_refresh=True` to bypass cache.
"""
from __future__ import annotations

from typing import Optional

from guardian.threat_intel.cache import ThreatIntelCache
from guardian.threat_intel.collector import ThreatIntelligenceCollector
from guardian.threat_intel.models import CVERecord, FeedMetadata, FeedSource, ThreatContext
from guardian.threat_intel.normalizer import CVENormalizer


class ThreatIntelRetriever:
    """
    Repository-pattern facade.
    Inject mock collector + cache in tests — no hardcoded paths or singletons.
    """

    def __init__(
        self,
        collector: Optional[ThreatIntelligenceCollector] = None,
        cache: Optional[ThreatIntelCache] = None,
        normalizer: Optional[CVENormalizer] = None,
    ):
        self._collector = collector or ThreatIntelligenceCollector()
        self._cache = cache or ThreatIntelCache()
        self._normalizer = normalizer or CVENormalizer()

    def lookup(
        self,
        package: str,
        version: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatContext:
        """
        Return a ThreatContext for the given package/version.
        Hits cache first; falls back to live fetch.
        """
        if not force_refresh:
            cached = self._cache.get(package, version)
            if cached is not None:
                normalised = self._normalizer.normalize_many(cached)
                return ThreatContext.from_cves(package, version or "any", normalised)

        # Live fetch
        raw = self._collector.collect(package, version)
        normalised = self._normalizer.normalize_many(raw)
        self._cache.put(package, version, normalised)
        return ThreatContext.from_cves(package, version or "any", normalised)

    def lookup_many(
        self,
        packages: list[tuple[str, Optional[str]]],
        force_refresh: bool = False,
    ) -> list[ThreatContext]:
        return [self.lookup(pkg, ver, force_refresh) for pkg, ver in packages]

    def enrich_epss(self, cves: list[CVERecord]) -> list[CVERecord]:
        """
        Placeholder for FIRST.org EPSS enrichment.
        Currently returns cves unchanged; wire in EPSS API here when available.
        For now, EPSS is estimated as cvss_score * 0.1 for non-zero CVSS records.
        """
        for cve in cves:
            if cve.epss_score < 0 and cve.cvss_score > 0:
                cve.epss_score = round(cve.cvss_score / 10 * 0.6, 4)
        return cves
