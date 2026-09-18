"""
Quantum Readiness Engine — Data Models
========================================
All quantum-specific types. Designed so future NIST PQC standard updates
can be applied by editing the migration map (in mapper.py) without touching
these model classes.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class QuantumThreat(str, Enum):
    CRITICAL = "Critical"      # broken by Shor's in polynomial time (RSA, ECC, DH)
    HIGH = "High"              # weakened by Grover's (AES-128, SHA-256)
    MEDIUM = "Medium"          # classically weak, quantum accelerates (SHA-1, MD5)
    LOW = "Low"                # configuration-level weakness (weak TLS/SSH version)
    NONE = "None"              # safe algorithm


class AlgorithmFamily(str, Enum):
    RSA = "RSA"
    ECC = "ECC"
    DSA = "DSA"
    DIFFIE_HELLMAN = "Diffie-Hellman"
    AES = "AES"
    SHA = "SHA"
    MD5 = "MD5"
    TLS = "TLS"
    SSH = "SSH"
    UNKNOWN = "Unknown"


@dataclass
class CryptoUsage:
    """
    A single detected use of a cryptographic algorithm in source code.
    """
    algorithm: str                 # e.g. "RSA", "SHA-1", "AES/ECB"
    family: AlgorithmFamily
    threat_level: QuantumThreat
    file: str
    line: int
    snippet: str
    key_size: Optional[int] = None  # bits, when detectable
    context: str = ""               # e.g. "encryption", "signing", "hashing"
    usage_id: str = field(default="", init=False)

    def __post_init__(self):
        basis = f"{self.file}:{self.line}:{self.algorithm}"
        self.usage_id = hashlib.sha256(basis.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["usage_id"] = self.usage_id
        return d


@dataclass
class MigrationRecommendation:
    """
    NIST PQC migration path for a detected vulnerable algorithm.
    Future NIST PQC updates: edit mapper.py; this model is stable.
    """
    vulnerable_algorithm: str
    replacement_algorithm: str
    nist_standard: str               # e.g. "FIPS 203 (ML-KEM)"
    rationale: str
    migration_effort: str            # "Low" / "Medium" / "High"
    example_code: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CryptographicBOM:
    """
    Cryptographic Bill of Materials — full inventory for a scanned target.
    Alias: CBOM.
    """
    target: str
    usages: list[CryptoUsage] = field(default_factory=list)

    @property
    def by_family(self) -> dict[str, list[CryptoUsage]]:
        out: dict[str, list[CryptoUsage]] = {}
        for u in self.usages:
            key = u.family.value
            out.setdefault(key, []).append(u)
        return out

    @property
    def critical_count(self) -> int:
        return sum(1 for u in self.usages if u.threat_level == QuantumThreat.CRITICAL)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_crypto_usages": len(self.usages),
            "critical_count": self.critical_count,
            "by_family": {k: [u.to_dict() for u in v] for k, v in self.by_family.items()},
        }


@dataclass
class QuantumReadinessReport:
    """
    Aggregate report returned by scorer.py.
    """
    readiness_score: float              # 0–100 (100 = fully quantum-ready)
    cbom: CryptographicBOM
    recommendations: list[MigrationRecommendation] = field(default_factory=list)
    files_scanned: int = 0

    def to_dict(self) -> dict:
        return {
            "readiness_score": round(self.readiness_score, 2),
            "files_scanned": self.files_scanned,
            "cbom": self.cbom.to_dict(),
            "recommendations": [r.to_dict() for r in self.recommendations],
        }
