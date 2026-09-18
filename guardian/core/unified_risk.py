"""
Unified Risk Engine
===================
Produces the final risk assessment from every deterministic and
contextual signal the pipeline gathered.

The composite formula from the original design document is preserved —
existing consumers of `guardian.core.risk` see no change — and extended
with the signals the refactor made available:

    severity            deterministic detector output
    confidence          detector self-report, discounted for AI findings
    exploitability      reachability from the UST data-flow pass
    business impact     business-domain and business-tag context
    business intent     alignment score from requirement-vs-code comparison
    quantum exposure    CBOM readiness, as a *separate* dimension
    dependency risk     SCA + KEV/threat intel
    AI confidence       contextual signals, capped and clearly attributed

**Nemotron never assigns the final score.** It contributes bounded
signals — a migration urgency, a business-impact judgement — which this
module folds in with fixed weights it does not control. A model that
returns "CRITICAL, confidence 1.0" for everything can move a finding's
contextual factor within a capped band and nothing else.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from guardian.core.models import Finding, ScanResult
from guardian.core.risk import (
    SEVERITY_TO_CVSS, SEVERITY_WEIGHT, RiskReport, compute_risk_report,
)

#: Contribution of each dimension to the finding-level composite score.
#: Deliberately sums to 1.0 and lives here, not in a prompt.
FINDING_WEIGHTS = {
    "severity": 0.30,
    "confidence": 0.20,
    "business_impact": 0.25,
    "reachability": 0.15,
    "exploit_likelihood": 0.10,
}

#: AI-sourced findings are damped: a contextual claim is a signal, not a
#: measurement, and must not outrank a proven data-flow finding.
SOURCE_MULTIPLIER = {
    "DETERMINISTIC": 1.0,
    "AI_VALIDATED": 0.85,
    "AI_SUGGESTED": 0.6,
    "INSUFFICIENT_EVIDENCE": 0.0,
}

#: Categories whose findings are inventory rather than live exposure.
#: They appear in every report but must not drive the security score.
NON_SCORING_CATEGORIES = {"Quantum Migration Inventory", "Quantum Readiness"}

#: Business tags that raise the impact of a finding in their vicinity.
HIGH_IMPACT_TAGS = {"payment", "refund", "money", "pii", "auth", "kyc",
                    "healthcare", "loan"}


@dataclass
class FindingRiskDetail:
    """Per-finding score with every input shown, so it can be argued with."""

    finding_id: str
    category: str
    severity: str
    source: str
    score: float
    severity_factor: float
    confidence_factor: float
    business_impact: float
    reachability: float
    exploit_likelihood: float
    source_multiplier: float
    evidence_count: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UnifiedRiskReport:
    """The platform's final risk assessment."""

    security_score: float                 # 0-100, higher is better
    alignment_score: float                # business intent alignment
    maintainability_score: float
    quantum_readiness_score: float
    dependency_risk_score: float          # 0-100, higher is better
    overall_risk_score: float             # composite, higher is better
    pr_risk: float                        # 0-100, higher is worse
    merge_decision: str
    finding_risks: list[FindingRiskDetail] = field(default_factory=list)
    dimensions: dict[str, Any] = field(default_factory=dict)
    ai_contribution: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "security_score": round(self.security_score, 2),
            "alignment_score": round(self.alignment_score, 2),
            "maintainability_score": round(self.maintainability_score, 2),
            "quantum_readiness_score": round(self.quantum_readiness_score, 2),
            "dependency_risk_score": round(self.dependency_risk_score, 2),
            "overall_risk_score": round(self.overall_risk_score, 2),
            "pr_risk": round(self.pr_risk, 2),
            "merge_decision": self.merge_decision,
            "dimensions": self.dimensions,
            "ai_contribution": self.ai_contribution,
            "findings": [f.to_dict() for f in self.finding_risks],
        }


# ---------------------------------------------------------------------------
def score_finding(finding: Finding, *, evidence_store=None,
                  business_domain: str = "",
                  kev_packages: Optional[set[str]] = None) -> FindingRiskDetail:
    """Score one finding across every available dimension."""
    notes: list[str] = []

    severity_factor = SEVERITY_TO_CVSS.get(finding.severity, 0.5)

    # Reachability: the data-flow pass is the strongest available signal.
    if finding.tainted:
        reachability = 1.0
        notes.append("data-flow confirmed a path from an untrusted source")
    elif finding.function:
        reachability = 0.7
        notes.append("located inside a named function")
    else:
        reachability = 0.5

    # Business impact from the tags on the evidence backing this finding.
    business_impact, impact_notes = _business_impact(
        finding, evidence_store, business_domain)
    notes.extend(impact_notes)

    exploit_likelihood = severity_factor * 0.6
    if kev_packages and any(pkg in (finding.snippet or "").lower()
                            for pkg in kev_packages):
        exploit_likelihood = 1.0
        notes.append("component appears in the CISA KEV catalog")

    multiplier = SOURCE_MULTIPLIER.get(finding.source, 0.6)
    if finding.source != "DETERMINISTIC":
        notes.append(f"contextual finding ({finding.source}); score damped "
                     f"by {multiplier:.2f}")

    raw = (
        severity_factor * FINDING_WEIGHTS["severity"]
        + finding.confidence * FINDING_WEIGHTS["confidence"]
        + business_impact * FINDING_WEIGHTS["business_impact"]
        + reachability * FINDING_WEIGHTS["reachability"]
        + exploit_likelihood * FINDING_WEIGHTS["exploit_likelihood"]
    ) * 100 * multiplier

    return FindingRiskDetail(
        finding_id=finding.finding_id,
        category=finding.category,
        severity=finding.severity,
        source=finding.source,
        score=round(raw, 2),
        severity_factor=round(severity_factor, 3),
        confidence_factor=round(finding.confidence, 3),
        business_impact=round(business_impact, 3),
        reachability=round(reachability, 3),
        exploit_likelihood=round(exploit_likelihood, 3),
        source_multiplier=multiplier,
        evidence_count=len(finding.evidence_ids),
        notes=notes,
    )


def _business_impact(finding: Finding, evidence_store,
                     business_domain: str) -> tuple[float, list[str]]:
    impact = 0.5
    notes: list[str] = []

    tags: set[str] = set()
    if evidence_store is not None:
        for eid in finding.evidence_ids:
            item = evidence_store.get(eid)
            if item is not None:
                tags |= set(item.tags)
                tags |= set((item.metadata or {}).get("business_tags", []) or [])

    hits = tags & HIGH_IMPACT_TAGS
    if hits:
        impact = 0.9
        notes.append(f"handles business-critical data ({', '.join(sorted(hits))})")
    elif business_domain and business_domain not in ("Unclassified", ""):
        impact = 0.65
        notes.append(f"repository classified as {business_domain}")

    if finding.category in ("Hardcoded Secret", "Broken Authentication"):
        impact = max(impact, 0.85)
    return impact, notes


# Real (OSV-sourced) vulnerabilities matter far more than an unpinned-but-
# not-known-vulnerable package; scoring them identically (the old flat
# "N findings * 8 points" penalty) made a repo with ten tidy pinned
# packages and a repo with two critical CVEs look about the same.
_DEPENDENCY_CATEGORIES = {"Vulnerable Dependency", "Unpinned Dependency"}
_DEPENDENCY_PENALTY = {"Critical": 18.0, "High": 12.0, "Medium": 6.0, "Low": 2.0, "Info": 1.0}


def _dependency_risk_score(scan_result: ScanResult, dependency_findings: int) -> float:
    dep_findings = [f for f in scan_result.findings if f.category in _DEPENDENCY_CATEGORIES]
    if not dep_findings:
        # Nothing categorized (e.g. a caller that only ever passed a raw
        # count, or the analyzer found nothing) -- keep the old, coarser
        # behaviour rather than silently reporting a perfect 100.
        return max(0.0, 100.0 - min(100.0, dependency_findings * 8.0))
    penalty = sum(_DEPENDENCY_PENALTY.get(f.severity, 4.0) for f in dep_findings)
    return max(0.0, 100.0 - min(100.0, penalty))


# ---------------------------------------------------------------------------
def compute_unified_risk(
    scan_result: ScanResult, *,
    evidence_store=None,
    alignment_score: float = 75.0,
    maintainability_score: float = 80.0,
    quantum_readiness: float = 100.0,
    business_domain: str = "",
    dependency_findings: int = 0,
    kev_packages: Optional[set[str]] = None,
    quantum_gate: bool = False,
) -> UnifiedRiskReport:
    """Fold every dimension into the final assessment.

    Quantum readiness is reported as its own dimension rather than being
    subtracted from the security score: an RSA-using payment system is not
    *insecure today*, and conflating the two produced a scanner that
    hard-blocked every real financial codebase.
    """
    scoring_findings = [f for f in scan_result.findings
                        if f.category not in NON_SCORING_CATEGORIES]
    inventory_findings = [f for f in scan_result.findings
                          if f.category in NON_SCORING_CATEGORIES]

    details = [score_finding(f, evidence_store=evidence_store,
                             business_domain=business_domain,
                             kev_packages=kev_packages)
               for f in scoring_findings]

    if not details:
        pr_risk = 0.0
    else:
        max_score = max(d.score for d in details)
        total_weight = sum(SEVERITY_WEIGHT.get(d.severity, 0.3) for d in details)
        weighted_avg = (
            sum(d.score * SEVERITY_WEIGHT.get(d.severity, 0.3) for d in details)
            / total_weight if total_weight else 0.0)
        pr_risk = max_score * 0.60 + weighted_avg * 0.40

    security_score = max(0.0, 100.0 - pr_risk)

    dependency_risk_score = _dependency_risk_score(scan_result, dependency_findings)

    # Composite: security and alignment dominate; quantum and dependency
    # posture contribute but cannot by themselves fail a healthy codebase.
    overall = (security_score * 0.40
               + alignment_score * 0.25
               + maintainability_score * 0.15
               + dependency_risk_score * 0.10
               + quantum_readiness * 0.10)

    ai_details = [d for d in details if d.source.startswith("AI")]
    ai_contribution = {
        "ai_findings": len(ai_details),
        "deterministic_findings": len(details) - len(ai_details),
        "max_ai_score": round(max((d.score for d in ai_details), default=0.0), 2),
        "note": ("Contextual findings are damped and never set the final score; "
                 "the weights above are fixed in the risk engine."),
    }

    report = UnifiedRiskReport(
        security_score=security_score,
        alignment_score=alignment_score,
        maintainability_score=maintainability_score,
        quantum_readiness_score=quantum_readiness,
        dependency_risk_score=dependency_risk_score,
        overall_risk_score=overall,
        pr_risk=pr_risk,
        merge_decision=_merge_decision(overall, alignment_score, security_score,
                                       quantum_gate and bool(inventory_findings)),
        finding_risks=sorted(details, key=lambda d: -d.score),
        dimensions={
            "security": round(security_score, 2),
            "business_alignment": round(alignment_score, 2),
            "maintainability": round(maintainability_score, 2),
            "dependency": round(dependency_risk_score, 2),
            "quantum_readiness": round(quantum_readiness, 2),
            "weights": {"security": 0.40, "business_alignment": 0.25,
                        "maintainability": 0.15, "dependency": 0.10,
                        "quantum_readiness": 0.10},
            "quantum_inventory_findings": len(inventory_findings),
        },
        ai_contribution=ai_contribution,
    )
    return report


def _merge_decision(overall: float, alignment: float, security: float,
                    quantum_gate_triggered: bool) -> str:
    """Mirrors the design document's merge-approval table.

    The PQC hard block stays opt-in: keying it on any Shor-class inventory
    finding blocked every repository that uses RSA today, which is all of
    them, making the gate meaningless.
    """
    if quantum_gate_triggered:
        return "Hard Block - PQC remediation plan mandatory"
    if alignment < 50:
        return "Block - Business intent mismatch must be resolved"
    risk = 100.0 - overall
    if risk <= 30 and alignment >= 80:
        return "Auto-Approve"
    if risk <= 60 and alignment >= 60:
        return "Warn - Merge Allowed (developer acknowledgement)"
    if risk <= 80:
        return "Block - Security Engineer waiver required"
    return "Hard Block - CISO approval + incident ticket"


# ---------------------------------------------------------------------------
def legacy_risk_report(scan_result: ScanResult, **kwargs) -> RiskReport:
    """The pre-refactor risk report, unchanged.

    Kept so existing callers and the `risk` key of the report dict keep
    working exactly as before while consumers migrate to `unified_risk`.
    """
    return compute_risk_report(scan_result, **kwargs)
