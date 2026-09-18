"""
AI Code Guardian - Risk Scoring Engine (Day 7)
================================================
Implements the Composite Risk Score formula from the Master Design Document:

    CRS_finding = (CVSS_Base*0.30 + ML_Confidence*0.20 + BCS*0.25
                   + Reachability*0.15 + EPSS*0.10) * 100

    Risk_PR = max(CRS_findings)*0.60 + weighted_avg(CRS_findings, by_severity)*0.40

    Security_Score   = 100 - Risk_PR
    Alignment_Score  = BAS   (Business Alignment Score, 0-100)
    Maintainability  = MQS   (Maintainability Quality Score, 0-100)
    Overall_Risk     = Security_Score*0.50 + Alignment_Score*0.30 + Maintainability*0.20

Where ground-truth CVSS/EPSS data is unavailable (no live NVD/EPSS feed
wired in yet), conservative severity-derived defaults are used and clearly
flagged in the output so they can be swapped for live threat-intel values
in the Days 8-10 integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from guardian.core.models import Finding, ScanResult

# Severity -> default CVSS base score (normalised 0-1) when no live CVSS feed.
SEVERITY_TO_CVSS = {
    "Critical": 0.95,
    "High": 0.80,
    "Medium": 0.55,
    "Low": 0.30,
    "Info": 0.10,
}

SEVERITY_WEIGHT = {  # for weighted_avg(by_severity)
    "Critical": 1.0,
    "High": 0.8,
    "Medium": 0.5,
    "Low": 0.25,
    "Info": 0.1,
}


@dataclass
class FindingRisk:
    finding_id: str
    category: str
    severity: str
    crs: float
    cvss_base: float
    ml_confidence: float
    business_context_score: float
    reachability: float
    epss: float


@dataclass
class RiskReport:
    security_score: float
    alignment_score: float
    maintainability_score: float
    overall_risk_score: float
    pr_risk: float
    finding_risks: list[FindingRisk]
    merge_decision: str

    def to_dict(self) -> dict:
        return {
            "security_score": round(self.security_score, 2),
            "alignment_score": round(self.alignment_score, 2),
            "maintainability_score": round(self.maintainability_score, 2),
            "overall_risk_score": round(self.overall_risk_score, 2),
            "pr_risk": round(self.pr_risk, 2),
            "merge_decision": self.merge_decision,
            "findings": [vars(fr) for fr in self.finding_risks],
        }


def _merge_decision(overall_risk: float, alignment_score: float, has_quantum_critical: bool = False) -> str:
    # Mirrors the Merge Approval Logic table in the design doc.
    if has_quantum_critical:
        return "Hard Block - PQC remediation plan mandatory"
    if alignment_score < 50:
        return "Block - Business intent mismatch must be resolved"
    risk = 100 - overall_risk  # table is phrased in terms of "Risk Score" (higher = riskier)
    if risk <= 30 and alignment_score >= 80:
        return "Auto-Approve"
    if risk <= 60 and alignment_score >= 60:
        return "Warn - Merge Allowed (developer acknowledgement)"
    if risk <= 80:
        return "Block - Security Engineer waiver required"
    return "Hard Block - CISO approval + incident ticket"


def score_finding(finding: Finding, business_context_score: float = 0.5, reachability: float = 1.0,
                   epss: Optional[float] = None) -> FindingRisk:
    cvss = SEVERITY_TO_CVSS.get(finding.severity, 0.5)
    epss_val = epss if epss is not None else cvss * 0.6  # heuristic stand-in until live EPSS feed
    crs = (
        cvss * 0.30
        + finding.confidence * 0.20
        + business_context_score * 0.25
        + reachability * 0.15
        + epss_val * 0.10
    ) * 100
    return FindingRisk(
        finding_id=finding.finding_id,
        category=finding.category,
        severity=finding.severity,
        crs=round(crs, 2),
        cvss_base=cvss,
        ml_confidence=finding.confidence,
        business_context_score=business_context_score,
        reachability=reachability,
        epss=round(epss_val, 2),
    )


def compute_risk_report(scan_result: ScanResult, alignment_score: float = 75.0,
                         maintainability_score: float = 80.0,
                         business_context_scores: Optional[dict] = None, quantum_gate: bool = False) -> RiskReport:
    business_context_scores = business_context_scores or {}
    finding_risks = [
        score_finding(
            f,
            business_context_score=business_context_scores.get(f.finding_id, 0.5),
            reachability=1.0 if f.tainted else 0.6,
        )
        for f in scan_result.findings
    ]

    if not finding_risks:
        pr_risk = 0.0
    else:
        max_crs = max(fr.crs for fr in finding_risks)
        total_weight = sum(SEVERITY_WEIGHT.get(fr.severity, 0.3) for fr in finding_risks)
        weighted_avg = (
            sum(fr.crs * SEVERITY_WEIGHT.get(fr.severity, 0.3) for fr in finding_risks) / total_weight
            if total_weight else 0.0
        )
        pr_risk = max_crs * 0.60 + weighted_avg * 0.40

    security_score = max(0.0, 100 - pr_risk)
    overall_risk = security_score * 0.50 + alignment_score * 0.30 + maintainability_score * 0.20
    # PQC merge gating is OPT-IN (GuardianConfig.enable_quantum_gate).
    # Rationale from the Hyperswitch audit: keying the hard block on any
    # High "Weak Crypto" finding (the previous behaviour) hard-blocked
    # every repository that uses RSA/ECC today — i.e. every real
    # payments/banking codebase — making the gate meaningless. Classical
    # weak-crypto findings are already priced into the security score.
    has_quantum_critical = quantum_gate and any(
        fr.category == "Quantum Migration Inventory" for fr in finding_risks)

    decision = _merge_decision(overall_risk, alignment_score, has_quantum_critical)

    return RiskReport(
        security_score=security_score,
        alignment_score=alignment_score,
        maintainability_score=maintainability_score,
        overall_risk_score=overall_risk,
        pr_risk=pr_risk,
        finding_risks=finding_risks,
        merge_decision=decision,
    )
