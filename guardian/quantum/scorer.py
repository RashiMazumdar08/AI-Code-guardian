"""
Quantum Readiness Engine — Scorer
====================================
Produces a QuantumReadinessReport and emits Finding objects compatible
with the existing Risk Scoring Engine.

Score formula
-------------
Penalty per usage:
    CRITICAL  = 25 pts
    HIGH      = 10 pts
    MEDIUM    =  5 pts
    LOW       =  2 pts

readiness_score = max(0, 100 - total_penalty)

This is intentionally simple and conservative. Live CVSS/EPSS data for
PQC findings can be piped in via the Threat Intelligence Engine later.
"""
from __future__ import annotations

from guardian.quantum.models import (
    CryptographicBOM, CryptoUsage, MigrationRecommendation,
    QuantumReadinessReport, QuantumThreat
)
from guardian.core.models import Finding, Severity

_PENALTY = {
    QuantumThreat.CRITICAL: 25,
    QuantumThreat.HIGH: 10,
    QuantumThreat.MEDIUM: 5,
    QuantumThreat.LOW: 2,
    QuantumThreat.NONE: 0,
}

_THREAT_TO_SEVERITY = {
    QuantumThreat.CRITICAL: Severity.CRITICAL.value,
    QuantumThreat.HIGH: Severity.HIGH.value,
    QuantumThreat.MEDIUM: Severity.MEDIUM.value,
    QuantumThreat.LOW: Severity.LOW.value,
    QuantumThreat.NONE: Severity.INFO.value,
}


class QuantumReadinessScorer:

    def score(
        self,
        cbom: CryptographicBOM,
        recommendations: list[MigrationRecommendation],
        files_scanned: int = 0,
    ) -> QuantumReadinessReport:
        total_penalty = sum(_PENALTY.get(u.threat_level, 0) for u in cbom.usages)
        readiness = max(0.0, 100.0 - total_penalty)
        return QuantumReadinessReport(
            readiness_score=round(readiness, 2),
            cbom=cbom,
            recommendations=recommendations,
            files_scanned=files_scanned,
        )

    def to_findings(self, cbom: CryptographicBOM) -> list[Finding]:
        findings: list[Finding] = []
        for usage in cbom.usages:
            if usage.threat_level == QuantumThreat.NONE:
                continue
            findings.append(Finding(
                category="Weak Crypto",
                severity=_THREAT_TO_SEVERITY[usage.threat_level],
                rule_id=f"QRE-{usage.family.value.upper()[:6]}",
                file=usage.file,
                line=usage.line,
                snippet=usage.snippet,
                recommendation=(
                    f"Quantum threat: {usage.threat_level.value}. "
                    f"Algorithm '{usage.algorithm}' ({usage.context}) is vulnerable. "
                    f"Migrate to a NIST PQC approved algorithm. See quantum readiness report."
                ),
                cwe="CWE-327",
                owasp="A02:2021",
                confidence=0.9,
                tainted=False,
            ))
        return findings
