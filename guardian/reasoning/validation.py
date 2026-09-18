"""
AI Finding Validation
=====================
The gate every model claim passes before it can appear in results.

    Nemotron response
      -> schema validation        (guardian.reasoning.schemas)
      -> evidence-ID validation   (does the cited evidence exist?)
      -> source validation        (do the file/line/function exist?)
      -> consistency validation   (does the evidence say what is claimed?)
      -> hallucination checks     (invented algorithms, unsupported claims)
      -> accepted Finding

Outcomes, never collapsed into one another:

    AI_VALIDATED           every check passed; the claim is grounded
    AI_SUGGESTED           evidence is real but the claim goes beyond what
                           it strictly proves — surfaced, clearly labelled,
                           and confidence-capped
    INSUFFICIENT_EVIDENCE  rejected; recorded with the reason so the
                           rejection is auditable rather than invisible

A model statement never becomes a confirmed vulnerability here. The most
an accepted claim can be is AI_VALIDATED, which reports and ranks
differently from DETERMINISTIC everywhere downstream.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from guardian.core.context import AnalysisContext
from guardian.core.models import Finding
from guardian.evidence.models import Evidence, FindingSource, ValidatedFinding
from guardian.reasoning.schemas import ReasoningFinding, ReasoningResponse
from guardian.ust.tagging import ALGORITHM_ALIASES

log = logging.getLogger(__name__)

#: Confidence ceiling for a claim that is grounded but not fully corroborated.
SUGGESTED_CONFIDENCE_CAP = 0.6
#: Confidence ceiling for any AI claim, however well-grounded. Deterministic
#: detection stays the only thing that reaches 1.0.
VALIDATED_CONFIDENCE_CAP = 0.9

#: Algorithm names the platform can actually classify. A claim naming
#: something outside this set is a fabrication risk, not a discovery.
KNOWN_ALGORITHMS = {name for _, name in ALGORITHM_ALIASES} | {
    "unknown", "AES-256", "AES-192", "AES-128", "PBKDF2", "HKDF", "HMAC",
}

_HEDGE = re.compile(r"(?i)\b(might|may|could|possibly|likely|appears|seems|"
                    r"suspect|probably|potentially|unclear|assume|presumably)\b")


@dataclass
class ValidationReport:
    """Audit record for one reasoning response."""

    accepted: list[ValidatedFinding] = field(default_factory=list)
    rejected: list[ValidatedFinding] = field(default_factory=list)
    schema_problems: list[str] = field(default_factory=list)

    @property
    def validated(self) -> list[ValidatedFinding]:
        return [f for f in self.accepted if f.source is FindingSource.AI_VALIDATED]

    @property
    def suggested(self) -> list[ValidatedFinding]:
        return [f for f in self.accepted if f.source is FindingSource.AI_SUGGESTED]

    def to_dict(self) -> dict:
        return {
            "accepted": len(self.accepted),
            "validated": len(self.validated),
            "suggested": len(self.suggested),
            "rejected": len(self.rejected),
            "schema_problems": self.schema_problems,
            "rejections": [
                {"reason": f.reason, "notes": f.validation_notes,
                 "evidence_ids": f.evidence_ids}
                for f in self.rejected
            ],
            "findings": [f.to_dict() for f in self.accepted],
        }


class AIFindingValidator:
    """Validates model claims against the evidence store and the repository."""

    def __init__(self, context: AnalysisContext, *,
                 allowed_evidence: Optional[Iterable[str]] = None) -> None:
        self.context = context
        self.store = context.evidence
        #: When set, restricts citations to the evidence actually sent for
        #: this task — citing a real ID that was never supplied means the
        #: model guessed an identifier that happened to exist.
        self.allowed_evidence = set(allowed_evidence) if allowed_evidence else None
        self._known_files = context.known_files()

    # ------------------------------------------------------------------
    def validate_response(self, response: ReasoningResponse) -> ValidationReport:
        report = ValidationReport(schema_problems=list(response.problems))
        for finding in response.findings:
            validated = self.validate_finding(finding)
            if validated.source is FindingSource.INSUFFICIENT_EVIDENCE:
                report.rejected.append(validated)
            else:
                report.accepted.append(validated)
        return report

    # ------------------------------------------------------------------
    def validate_finding(self, claim: ReasoningFinding) -> ValidatedFinding:
        notes: list[str] = []
        downgrade = False

        # 1. Evidence must exist ---------------------------------------
        resolved, missing = self.store.resolve(claim.evidence_ids)
        if missing:
            notes.append(f"cites non-existent evidence: {', '.join(missing)}")
        if not resolved:
            return self._reject(claim, notes or ["no valid evidence cited"])

        # 2. Evidence must have been supplied for this task -------------
        if self.allowed_evidence is not None:
            out_of_scope = [e.id for e in resolved if e.id not in self.allowed_evidence]
            if out_of_scope:
                notes.append("cites evidence not supplied for this task: "
                             + ", ".join(out_of_scope))
                resolved = [e for e in resolved if e.id in self.allowed_evidence]
                if not resolved:
                    return self._reject(claim, notes)
                downgrade = True

        # 3. Source location must exist ---------------------------------
        location_ok, location_notes = self._validate_location(claim, resolved)
        notes.extend(location_notes)
        if not location_ok:
            downgrade = True

        # 4. Algorithm claims must be ones we can classify ---------------
        algorithm_ok, algorithm_notes = self._validate_algorithms(claim, resolved)
        notes.extend(algorithm_notes)
        if not algorithm_ok:
            return self._reject(claim, notes)

        # 5. The claim must not contradict its evidence ------------------
        # Naming an algorithm the evidence does not contain, or asserting a
        # missing control with nothing behavioural behind it, is a factual
        # error about the code rather than an over-confident phrasing — so
        # it is rejected outright rather than surfaced as a suggestion.
        consistent, consistency_notes = self._validate_consistency(claim, resolved)
        notes.extend(consistency_notes)
        if not consistent:
            return self._reject(claim, notes)

        # 6. Hedged language is a suggestion, not a validated finding -----
        if _HEDGE.search(claim.reason or ""):
            notes.append("reasoning is hedged rather than asserted")
            downgrade = True

        if not claim.reason.strip():
            return self._reject(claim, notes + ["no reasoning supplied"])

        primary = resolved[0]
        source = FindingSource.AI_SUGGESTED if downgrade else FindingSource.AI_VALIDATED
        cap = SUGGESTED_CONFIDENCE_CAP if downgrade else VALIDATED_CONFIDENCE_CAP

        return ValidatedFinding(
            category=claim.category or "contextual_analysis",
            severity=claim.severity,
            confidence=round(min(claim.confidence, cap), 3),
            reason=claim.reason,
            recommendation=claim.recommendation,
            evidence_ids=[e.id for e in resolved],
            source=source,
            file=claim.file or primary.file,
            line=claim.line or primary.line,
            function=claim.function or primary.symbol,
            language=primary.language,
            title=claim.title,
            validation_notes=notes,
            metadata=dict(claim.extras),
        )

    # ------------------------------------------------------------------
    def _reject(self, claim: ReasoningFinding, notes: list[str]) -> ValidatedFinding:
        log.info("rejected AI claim (%s): %s", claim.category or "?", "; ".join(notes))
        return ValidatedFinding(
            category=claim.category or "contextual_analysis",
            severity="Info",
            confidence=0.0,
            reason=claim.reason,
            recommendation=claim.recommendation,
            evidence_ids=claim.evidence_ids,
            source=FindingSource.INSUFFICIENT_EVIDENCE,
            file=claim.file, line=claim.line, function=claim.function,
            title=claim.title,
            validation_notes=notes,
            metadata=dict(claim.extras),
        )

    # ------------------------------------------------------------------
    def _validate_location(self, claim: ReasoningFinding,
                           evidence: list[Evidence]) -> tuple[bool, list[str]]:
        notes: list[str] = []
        ok = True

        if claim.file:
            normalised = claim.file.replace("\\", "/")
            evidence_files = {e.file for e in evidence}
            if normalised not in evidence_files and normalised not in self._known_files:
                if not self._file_exists(normalised):
                    notes.append(f"references file '{claim.file}' which is not in "
                                 f"the scanned repository")
                    ok = False
            elif normalised not in evidence_files:
                notes.append(f"references file '{claim.file}' which exists but is not "
                             f"the file the cited evidence is in")
                ok = False

        if claim.line:
            evidence_lines = {e.line for e in evidence}
            near = any(abs(claim.line - line) <= 5 for line in evidence_lines if line)
            if not near:
                line_count = self._line_count(claim.file or (evidence[0].file if evidence else ""))
                if line_count is not None and claim.line > line_count:
                    notes.append(f"line {claim.line} is beyond the end of the file "
                                 f"({line_count} lines)")
                else:
                    notes.append(f"line {claim.line} does not match any cited evidence "
                                 f"location {sorted(evidence_lines)}")
                ok = False

        if claim.function:
            known = self.context.known_functions(claim.file) if claim.file \
                else self.context.known_functions()
            evidence_symbols = {e.symbol for e in evidence if e.symbol}
            if claim.function not in known and claim.function not in evidence_symbols:
                notes.append(f"references function '{claim.function}' which does not "
                             f"exist in the parsed code")
                ok = False

        return ok, notes

    def _validate_algorithms(self, claim: ReasoningFinding,
                             evidence: list[Evidence]) -> tuple[bool, list[str]]:
        """Reject invented cryptographic algorithms.

        A model asked about RSA that answers about a scheme we have no
        classification for is not making a discovery; it is producing an
        unverifiable claim in the one place — crypto — where the whole
        value of the output is that it can be checked.
        """
        claimed = str(claim.extras.get("recommended_pqc_algorithm") or "").strip()
        if not claimed:
            return True, []
        if claimed in KNOWN_ALGORITHMS:
            return True, []
        # tolerate parameter-set spellings: ML-KEM-768, Dilithium3, AES-256-GCM
        from guardian.ust.tagging import resolve_algorithm
        if resolve_algorithm(claimed):
            return True, []
        return False, [f"recommends unsupported algorithm '{claimed}'"]

    def _validate_consistency(self, claim: ReasoningFinding,
                              evidence: list[Evidence]) -> tuple[bool, list[str]]:
        """Cheap semantic cross-check between the claim and its evidence."""
        notes: list[str] = []
        text = f"{claim.reason} {claim.recommendation} {claim.title}".lower()

        # An algorithm named in the reasoning should appear in the evidence.
        evidence_algorithms = {
            str((e.metadata or {}).get("algorithm", "")).lower()
            for e in evidence} - {""}
        if evidence_algorithms:
            mentioned = {name.lower() for _, name in ALGORITHM_ALIASES
                         if re.search(rf"\b{re.escape(name.lower())}\b", text)}
            # migration targets legitimately name algorithms not in the code
            targets = {"ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "ntru", "frodokem",
                       "pqc-kem", "aes-256", "sha-384", "sha-512", "sha-3", "argon2",
                       "bcrypt", "scrypt", "chacha20", "x25519", "ed25519", "tls1.3"}
            unexplained = mentioned - evidence_algorithms - targets
            if unexplained:
                notes.append("mentions algorithm(s) absent from the cited evidence: "
                             + ", ".join(sorted(unexplained)))
                return False, notes

        # A claim that a control is missing must cite evidence that says so.
        if re.search(r"(?i)\b(no|missing|absent|lacks?|without)\b[^.]{0,40}"
                     r"\b(authorization|approval|check|validation|control)\b", text):
            supports_absence = any(
                e.type.value in ("missing_control", "behavior", "authorization_check",
                                 "business_policy", "code_structure")
                for e in evidence)
            if not supports_absence:
                notes.append("asserts a missing control without behavioural evidence")
                return False, notes

        return True, notes

    # ------------------------------------------------------------------
    def _file_exists(self, relative: str) -> bool:
        try:
            return (Path(self.context.repository.root) / relative).is_file()
        except OSError:
            return False

    def _line_count(self, relative: str) -> Optional[int]:
        if not relative:
            return None
        ust_file = self.context.ust_file(relative)
        if ust_file is not None and ust_file.line_count:
            return ust_file.line_count
        try:
            with open(Path(self.context.repository.root) / relative, "rb") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return None


# ---------------------------------------------------------------------------
def to_findings(validated: Iterable[ValidatedFinding], *, engine: str,
                default_category: str = "") -> list[Finding]:
    """Convert accepted AI claims into pipeline Findings.

    `source` carries the provenance through to every report and to the
    risk engine, so an AI claim is never silently indistinguishable from
    a deterministic detection.
    """
    findings: list[Finding] = []
    for item in validated:
        if not item.accepted:
            continue
        findings.append(Finding(
            category=item.category or default_category or "Contextual Finding",
            severity=item.severity,
            rule_id=f"AI-{(item.category or engine).upper().replace(' ', '-')[:20]}",
            file=item.file,
            line=item.line,
            snippet=item.title or item.reason[:200],
            recommendation=item.recommendation,
            confidence=item.confidence,
            language=item.language,
            function=item.function,
            evidence_ids=list(item.evidence_ids),
            source=item.source.value,
            reason=item.reason,
            engine=engine,
        ))
    return findings
