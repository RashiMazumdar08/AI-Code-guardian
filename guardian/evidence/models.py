"""
Shared Evidence Model
=====================
Evidence is what a *deterministic* engine observed. It is not a verdict.

    rule / UST pattern  ->  candidate Evidence  ->  contextual analysis
                                                ->  validated Finding

Every engine (SAST, secrets, SCA, IaC, crypto, business behaviour,
threat intel, config) publishes Evidence into the repository-level
EvidenceStore. Reasoning layers then select a *small* relevant subset,
never raw repository dumps, and any AI claim must cite evidence IDs that
already exist in the store.

Evidence IDs are stable and human-quotable: E1, E2, ... assigned by the
store in publication order, with the content hash kept in `fingerprint`
so the same observation dedupes across engines.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class EvidenceType(str, Enum):
    """What kind of observation this is."""

    # security / SAST
    VULNERABILITY_PATTERN = "vulnerability_pattern"
    TAINT_FLOW = "taint_flow"
    SECRET = "secret"
    INSECURE_CONFIGURATION = "insecure_configuration"

    # crypto / quantum
    CRYPTO_USAGE = "crypto_usage"
    CRYPTO_DEPENDENCY = "crypto_dependency"

    # supply chain
    DEPENDENCY = "dependency"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    THREAT_INTEL = "threat_intel"

    # infrastructure
    IAC_MISCONFIGURATION = "iac_misconfiguration"

    # code structure / behaviour
    CODE_STRUCTURE = "code_structure"
    BEHAVIOR = "behavior"
    MISSING_CONTROL = "missing_control"
    AUTHORIZATION_CHECK = "authorization_check"
    API_ENDPOINT = "api_endpoint"
    DATABASE_OPERATION = "database_operation"

    # business
    BUSINESS_POLICY = "business_policy"
    BUSINESS_DOMAIN = "business_domain"

    OTHER = "other"


class FindingSource(str, Enum):
    """Provenance of a finding — never conflate these in a report."""

    DETERMINISTIC = "DETERMINISTIC"            # rules/UST proved it
    AI_VALIDATED = "AI_VALIDATED"              # LLM claim that passed evidence validation
    AI_SUGGESTED = "AI_SUGGESTED"              # LLM claim, plausible but not fully validated
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # claim rejected / not provable


@dataclass
class Evidence:
    """One deterministic observation, grounded in a real source location."""

    type: EvidenceType
    source: str                       # producing engine, e.g. "ust_crypto_detector"
    file: str = ""
    line: int = 0
    end_line: int = 0
    column: int = 0
    language: str = ""
    symbol: str = ""                  # function/class/identifier the observation attaches to
    operation: str = ""               # short human phrase, e.g. "RSA encryption"
    description: str = ""
    snippet: str = ""
    confidence: float = 1.0           # 1.0 = directly observed in the syntax tree
    severity_hint: str = ""           # optional; the risk engine decides the real severity
    node_id: str = ""                 # originating USTNode, when applicable
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    id: str = ""                      # assigned by the EvidenceStore ("E12")
    fingerprint: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if isinstance(self.type, str) and not isinstance(self.type, EvidenceType):
            try:
                self.type = EvidenceType(self.type)
            except ValueError:
                self.type = EvidenceType.OTHER
        basis = (f"{self.type.value}|{self.source}|{self.file}|{self.line}|"
                 f"{self.symbol}|{self.operation}")
        self.fingerprint = hashlib.sha256(basis.encode()).hexdigest()[:16]

    # -- serialisation --------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["id"] = self.id
        d["fingerprint"] = self.fingerprint
        return d

    def to_context_line(self) -> str:
        """Compact single-line rendering for LLM prompts.

        Deliberately excludes the raw snippet: prompts get facts and
        locations, not bulk source. Callers that genuinely need a snippet
        attach it explicitly and sparingly.
        """
        bits = [f"{self.id or '?'}: {self.type.value}"]
        if self.operation:
            bits.append(self.operation)
        loc = self.file + (f":{self.line}" if self.line else "")
        if loc:
            bits.append(f"at {loc}")
        if self.symbol:
            bits.append(f"in {self.symbol}")
        if self.language:
            bits.append(f"[{self.language}]")
        bits.append(f"confidence={self.confidence:.2f}")
        return " | ".join(bits)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.file else ""


@dataclass
class ValidatedFinding:
    """An AI-produced claim that survived evidence validation.

    Kept separate from `guardian.core.models.Finding` so the validation
    layer can express *rejection* (`source=INSUFFICIENT_EVIDENCE`) without
    that ever entering the deterministic finding list by accident.
    """

    category: str
    severity: str
    confidence: float
    reason: str
    recommendation: str
    evidence_ids: list[str] = field(default_factory=list)
    source: FindingSource = FindingSource.AI_SUGGESTED
    file: str = ""
    line: int = 0
    function: str = ""
    language: str = ""
    title: str = ""
    validation_notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.source in (FindingSource.AI_VALIDATED, FindingSource.AI_SUGGESTED)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = self.source.value
        return d
