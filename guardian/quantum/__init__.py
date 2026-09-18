from __future__ import annotations

from guardian.quantum.models import (
    CryptoUsage, CryptographicBOM, QuantumReadinessReport,
    MigrationRecommendation, QuantumThreat, AlgorithmFamily,
)
from guardian.quantum.detector import QuantumDetector
from guardian.quantum.inventory import CryptoInventoryBuilder
from guardian.quantum.mapper import MigrationMapper
from guardian.quantum.scorer import QuantumReadinessScorer
from guardian.core.models import Finding

from pathlib import Path
from typing import Union


class QuantumReadinessEngine:
    """
    Facade: detect → inventory → map → score → emit findings.
    """

    def __init__(
        self,
        detector: QuantumDetector | None = None,
        mapper: MigrationMapper | None = None,
        scorer: QuantumReadinessScorer | None = None,
    ):
        self._detector = detector or QuantumDetector()
        self._inventory = CryptoInventoryBuilder()
        self._mapper = mapper or MigrationMapper()
        self._scorer = scorer or QuantumReadinessScorer()

    def analyze(
        self,
        target: Union[str, Path],
    ) -> tuple[QuantumReadinessReport, list[Finding]]:
        target = Path(target)
        if target.is_dir():
            usages = self._detector.scan_directory(target)
            files_scanned = len({u.file for u in usages})
        else:
            text = target.read_text(encoding="utf-8", errors="ignore")
            usages = self._detector.scan_text(text, str(target))
            files_scanned = 1

        cbom = self._inventory.build(usages, str(target))
        recommendations = self._mapper.map_usages(usages)
        report = self._scorer.score(cbom, recommendations, files_scanned)
        findings = self._scorer.to_findings(cbom)
        return report, findings
