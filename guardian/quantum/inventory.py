"""
Quantum Readiness Engine — Inventory
======================================
Builds a Cryptographic Bill of Materials (CBOM) from a list of CryptoUsage
objects produced by the Detector.
"""
from __future__ import annotations

from guardian.quantum.models import CryptographicBOM, CryptoUsage


class CryptoInventoryBuilder:
    """
    Aggregates raw CryptoUsage objects into a structured CBOM.
    """

    def build(self, usages: list[CryptoUsage], target: str = "unknown") -> CryptographicBOM:
        return CryptographicBOM(target=target, usages=usages)

    def summary(self, cbom: CryptographicBOM) -> dict:
        from collections import Counter
        threat_counts = Counter(u.threat_level.value for u in cbom.usages)
        family_counts = Counter(u.family.value for u in cbom.usages)
        top_files: dict[str, int] = {}
        for u in cbom.usages:
            top_files[u.file] = top_files.get(u.file, 0) + 1
        top5 = sorted(top_files.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "target": cbom.target,
            "total_crypto_usages": len(cbom.usages),
            "by_threat": dict(threat_counts),
            "by_family": dict(family_counts),
            "top_files": top5,
        }
