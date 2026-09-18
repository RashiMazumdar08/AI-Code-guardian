"""
Quantum Readiness — Layer B: Deterministic Classification
=========================================================
Layer A (the UST crypto discovery in `guardian.engines.quantum`) answers
*what cryptography is used and where*. This module answers *what that
means*, using trusted, citable rules only — no model is involved, and no
classification is ever inferred from prose.

Classification axes
-------------------
`QuantumStatus`
    VULNERABLE   broken by Shor's algorithm (RSA, ECC, ECDSA, ECDH, DSA, DH)
    WEAKENED     effective strength halved by Grover (AES-128, SHA-256 ...)
    BROKEN       already broken classically (MD5, SHA-1, DES, RC4)
    PQC          NIST post-quantum standard or candidate (ML-KEM, ML-DSA ...)
    SAFE         adequate post-quantum margin today (AES-256, SHA-384 ...)
    UNKNOWN      crypto observed, algorithm not resolvable from the code

`UNKNOWN` is a first-class outcome. When `Cipher.getInstance(algo)` takes
a runtime variable we record that crypto happens there and that we cannot
name the algorithm. Guessing would put an unfounded claim into a CBOM
that compliance teams rely on.

Migration targets come from `guardian.quantum.mapper.MIGRATION_MAP`
(FIPS 203/204/205), so the existing NIST knowledge stays the single place
to update when the standards move.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from guardian.quantum.models import AlgorithmFamily, QuantumThreat


class QuantumStatus(str, Enum):
    VULNERABLE = "quantum_vulnerable"
    WEAKENED = "quantum_weakened"
    BROKEN = "classically_broken"
    PQC = "post_quantum"
    SAFE = "quantum_safe"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AlgorithmClass:
    """Deterministic classification of one algorithm."""

    algorithm: str
    status: QuantumStatus
    family: AlgorithmFamily
    threat: QuantumThreat
    rationale: str
    migration_target: str = ""
    nist_standard: str = ""
    classical_strength_bits: int = 0
    post_quantum_strength_bits: int = 0

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "status": self.status.value,
            "family": self.family.value,
            "threat": self.threat.value,
            "rationale": self.rationale,
            "migration_target": self.migration_target,
            "nist_standard": self.nist_standard,
            "classical_strength_bits": self.classical_strength_bits,
            "post_quantum_strength_bits": self.post_quantum_strength_bits,
        }


def _c(algorithm, status, family, threat, rationale, migration="", standard="",
       classical=0, pq=0) -> AlgorithmClass:
    return AlgorithmClass(algorithm=algorithm, status=status, family=family,
                          threat=threat, rationale=rationale,
                          migration_target=migration, nist_standard=standard,
                          classical_strength_bits=classical,
                          post_quantum_strength_bits=pq)


_SHOR = "Broken in polynomial time by Shor's algorithm on a cryptographically relevant quantum computer."
_GROVER = "Grover's algorithm halves the effective key strength; the classical algorithm itself is sound."

#: The classification table. Keys are the canonical algorithm names
#: produced by `guardian.ust.tagging.resolve_algorithm`.
CLASSIFICATIONS: dict[str, AlgorithmClass] = {
    # -- Shor-vulnerable public-key -----------------------------------
    "RSA": _c("RSA", QuantumStatus.VULNERABLE, AlgorithmFamily.RSA,
              QuantumThreat.CRITICAL, _SHOR,
              "ML-KEM (key establishment) / ML-DSA (signatures)",
              "FIPS 203 / FIPS 204", classical=112, pq=0),
    "ECC": _c("ECC", QuantumStatus.VULNERABLE, AlgorithmFamily.ECC,
              QuantumThreat.CRITICAL, _SHOR, "ML-KEM / ML-DSA",
              "FIPS 203 / FIPS 204", classical=128, pq=0),
    "ECDSA": _c("ECDSA", QuantumStatus.VULNERABLE, AlgorithmFamily.ECC,
                QuantumThreat.CRITICAL, _SHOR, "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
                "FIPS 204 / FIPS 205", classical=128, pq=0),
    "ECDH": _c("ECDH", QuantumStatus.VULNERABLE, AlgorithmFamily.ECC,
               QuantumThreat.CRITICAL, _SHOR, "ML-KEM (Kyber), hybrid X25519+ML-KEM in transition",
               "FIPS 203", classical=128, pq=0),
    "X25519": _c("X25519", QuantumStatus.VULNERABLE, AlgorithmFamily.ECC,
                 QuantumThreat.CRITICAL, _SHOR, "Hybrid X25519+ML-KEM key exchange",
                 "FIPS 203", classical=128, pq=0),
    "Ed25519": _c("Ed25519", QuantumStatus.VULNERABLE, AlgorithmFamily.ECC,
                  QuantumThreat.CRITICAL, _SHOR, "ML-DSA or SLH-DSA",
                  "FIPS 204 / FIPS 205", classical=128, pq=0),
    "DSA": _c("DSA", QuantumStatus.VULNERABLE, AlgorithmFamily.DSA,
              QuantumThreat.CRITICAL, _SHOR, "ML-DSA (Dilithium)", "FIPS 204",
              classical=112, pq=0),
    "DH": _c("DH", QuantumStatus.VULNERABLE, AlgorithmFamily.DIFFIE_HELLMAN,
             QuantumThreat.CRITICAL, _SHOR, "ML-KEM (Kyber)", "FIPS 203",
             classical=112, pq=0),

    # -- NIST PQC ------------------------------------------------------
    "ML-KEM": _c("ML-KEM", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                 QuantumThreat.NONE,
                 "NIST-standardised module-lattice key encapsulation; no known quantum attack.",
                 standard="FIPS 203", classical=128, pq=128),
    "ML-DSA": _c("ML-DSA", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                 QuantumThreat.NONE,
                 "NIST-standardised module-lattice digital signature; no known quantum attack.",
                 standard="FIPS 204", classical=128, pq=128),
    "SLH-DSA": _c("SLH-DSA", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                  QuantumThreat.NONE,
                  "NIST-standardised stateless hash-based signature; conservative security basis.",
                  standard="FIPS 205", classical=128, pq=128),
    "FN-DSA": _c("FN-DSA", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                 QuantumThreat.NONE,
                 "NTRU-lattice signature scheme selected by NIST (FALCON); draft standard.",
                 standard="FIPS 206 (draft)", classical=128, pq=128),
    "NTRU": _c("NTRU", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN, QuantumThreat.NONE,
               "Lattice-based KEM; not a NIST primary standard but quantum-resistant.",
               standard="—", classical=128, pq=128),
    "FrodoKEM": _c("FrodoKEM", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                   QuantumThreat.NONE,
                   "Plain-LWE KEM; conservative alternative, ISO-track rather than FIPS.",
                   standard="—", classical=128, pq=128),
    "PQC-KEM": _c("PQC-KEM", QuantumStatus.PQC, AlgorithmFamily.UNKNOWN,
                  QuantumThreat.NONE,
                  "Post-quantum KEM candidate (HQC/BIKE/Classic McEliece).",
                  standard="—", classical=128, pq=128),

    # -- classically broken ---------------------------------------------
    "MD5": _c("MD5", QuantumStatus.BROKEN, AlgorithmFamily.MD5, QuantumThreat.MEDIUM,
              "Practical collisions since 2004; unusable for any security purpose.",
              "SHA-256 minimum, SHA-384 recommended", "NIST SP 800-107r1"),
    "MD4": _c("MD4", QuantumStatus.BROKEN, AlgorithmFamily.MD5, QuantumThreat.MEDIUM,
              "Fully broken.", "SHA-384", "NIST SP 800-107r1"),
    "SHA-1": _c("SHA-1", QuantumStatus.BROKEN, AlgorithmFamily.SHA, QuantumThreat.MEDIUM,
                "Chosen-prefix collisions demonstrated; NIST-deprecated for all uses.",
                "SHA-384 or SHA3-256", "NIST SP 800-107r1"),
    "DES": _c("DES", QuantumStatus.BROKEN, AlgorithmFamily.UNKNOWN, QuantumThreat.MEDIUM,
              "56-bit key, brute-forceable classically.", "AES-256-GCM", "NIST SP 800-131A"),
    "3DES": _c("3DES", QuantumStatus.BROKEN, AlgorithmFamily.UNKNOWN, QuantumThreat.MEDIUM,
               "Deprecated by NIST; 64-bit block size enables Sweet32.",
               "AES-256-GCM", "NIST SP 800-131A"),
    "RC4": _c("RC4", QuantumStatus.BROKEN, AlgorithmFamily.UNKNOWN, QuantumThreat.MEDIUM,
              "Biased keystream; practical plaintext recovery.", "AES-256-GCM or ChaCha20-Poly1305"),
    "Blowfish": _c("Blowfish", QuantumStatus.BROKEN, AlgorithmFamily.UNKNOWN,
                   QuantumThreat.MEDIUM, "64-bit block size; superseded.", "AES-256-GCM"),

    # -- Grover-weakened symmetric / hashes -------------------------------
    "AES-128": _c("AES-128", QuantumStatus.WEAKENED, AlgorithmFamily.AES,
                  QuantumThreat.MEDIUM, _GROVER + " AES-128 falls to ~64-bit quantum security.",
                  "AES-256", "NIST SP 800-175Br1", classical=128, pq=64),
    "AES-192": _c("AES-192", QuantumStatus.WEAKENED, AlgorithmFamily.AES,
                  QuantumThreat.LOW, _GROVER, "AES-256", "NIST SP 800-175Br1",
                  classical=192, pq=96),
    "AES": _c("AES", QuantumStatus.WEAKENED, AlgorithmFamily.AES, QuantumThreat.LOW,
              _GROVER + " Key size not resolvable from the call site; verify it is 256-bit.",
              "AES-256", "NIST SP 800-175Br1"),
    "SHA-224": _c("SHA-224", QuantumStatus.WEAKENED, AlgorithmFamily.SHA,
                  QuantumThreat.MEDIUM, _GROVER, "SHA-384", "NIST SP 800-107r1",
                  classical=112, pq=56),
    "SHA-256": _c("SHA-256", QuantumStatus.WEAKENED, AlgorithmFamily.SHA,
                  QuantumThreat.LOW,
                  "Grover reduces preimage resistance to ~128 bits — still adequate for most "
                  "uses; SHA-384 gives a larger margin for long-lived data.",
                  "SHA-384 or SHA3-256", "NIST SP 800-107r1", classical=256, pq=128),

    # -- adequate today ---------------------------------------------------
    "AES-256": _c("AES-256", QuantumStatus.SAFE, AlgorithmFamily.AES, QuantumThreat.NONE,
                  "128-bit post-quantum security under Grover; NIST-approved for PQ use.",
                  standard="NIST SP 800-175Br1", classical=256, pq=128),
    "SHA-384": _c("SHA-384", QuantumStatus.SAFE, AlgorithmFamily.SHA, QuantumThreat.NONE,
                  "192-bit post-quantum preimage resistance.",
                  standard="NIST SP 800-107r1", classical=384, pq=192),
    "SHA-512": _c("SHA-512", QuantumStatus.SAFE, AlgorithmFamily.SHA, QuantumThreat.NONE,
                  "256-bit post-quantum preimage resistance.",
                  standard="NIST SP 800-107r1", classical=512, pq=256),
    "SHA-3": _c("SHA-3", QuantumStatus.SAFE, AlgorithmFamily.SHA, QuantumThreat.NONE,
                "Sponge construction with adequate post-quantum margins.",
                standard="FIPS 202", classical=256, pq=128),
    "BLAKE2": _c("BLAKE2", QuantumStatus.SAFE, AlgorithmFamily.SHA, QuantumThreat.NONE,
                 "No known quantum shortcut beyond Grover."),
    "ChaCha20": _c("ChaCha20", QuantumStatus.SAFE, AlgorithmFamily.UNKNOWN,
                   QuantumThreat.NONE, "256-bit stream cipher; Grover-adequate.",
                   classical=256, pq=128),
    "Argon2": _c("Argon2", QuantumStatus.SAFE, AlgorithmFamily.UNKNOWN, QuantumThreat.NONE,
                 "Memory-hard password KDF; the recommended choice for password storage."),
    "bcrypt": _c("bcrypt", QuantumStatus.SAFE, AlgorithmFamily.UNKNOWN, QuantumThreat.NONE,
                 "Adaptive password hash; acceptable for password storage."),
    "scrypt": _c("scrypt", QuantumStatus.SAFE, AlgorithmFamily.UNKNOWN, QuantumThreat.NONE,
                 "Memory-hard password KDF."),
    "PBKDF2": _c("PBKDF2", QuantumStatus.SAFE, AlgorithmFamily.UNKNOWN, QuantumThreat.LOW,
                 "Acceptable with a high iteration count; Argon2id is preferred for new work."),

    # -- transport --------------------------------------------------------
    "TLS1.3": _c("TLS1.3", QuantumStatus.WEAKENED, AlgorithmFamily.TLS, QuantumThreat.LOW,
                 "Current TLS version, but its default key exchange (X25519/ECDHE) is "
                 "Shor-vulnerable until a hybrid PQC group is negotiated.",
                 "X25519MLKEM768 hybrid key exchange", "NIST SP 800-52r2"),
    "TLS1.2": _c("TLS1.2", QuantumStatus.WEAKENED, AlgorithmFamily.TLS, QuantumThreat.LOW,
                 "Supported but superseded; ECDHE key exchange is Shor-vulnerable.",
                 "TLS 1.3 with hybrid PQC key exchange", "NIST SP 800-52r2"),
    "TLS1.0/1.1": _c("TLS1.0/1.1", QuantumStatus.BROKEN, AlgorithmFamily.TLS,
                     QuantumThreat.LOW, "Deprecated (RFC 8996); known classical weaknesses.",
                     "TLS 1.3", "NIST SP 800-52r2"),
    "SSLv3": _c("SSLv3", QuantumStatus.BROKEN, AlgorithmFamily.TLS, QuantumThreat.LOW,
                "Broken by POODLE; prohibited.", "TLS 1.3", "NIST SP 800-52r2"),
}

#: Statuses that a CBOM must call out as requiring a migration plan.
MIGRATION_REQUIRED = {QuantumStatus.VULNERABLE, QuantumStatus.BROKEN}


UNKNOWN_CLASSIFICATION = AlgorithmClass(
    algorithm="unknown",
    status=QuantumStatus.UNKNOWN,
    family=AlgorithmFamily.UNKNOWN,
    threat=QuantumThreat.LOW,
    rationale=("A cryptographic API is invoked but the algorithm is supplied at runtime, "
               "so it cannot be determined statically. Review this call site manually."),
    migration_target="Determine the configured algorithm, then re-assess.",
)


def classify(algorithm: str) -> AlgorithmClass:
    """Classify a canonical algorithm name. Never raises, never guesses."""
    if not algorithm or algorithm.lower() in ("unknown", ""):
        return UNKNOWN_CLASSIFICATION
    found = CLASSIFICATIONS.get(algorithm)
    if found is not None:
        return found
    # canonical names are produced upstream; a miss means a new algorithm
    # we have no trusted rule for — say so rather than assume it is safe.
    return AlgorithmClass(
        algorithm=algorithm, status=QuantumStatus.UNKNOWN,
        family=AlgorithmFamily.UNKNOWN, threat=QuantumThreat.LOW,
        rationale=f"No trusted classification rule exists for '{algorithm}'.",
        migration_target="Assess manually against NIST PQC guidance.")


def is_quantum_vulnerable(algorithm: str) -> bool:
    return classify(algorithm).status is QuantumStatus.VULNERABLE


def is_post_quantum(algorithm: str) -> bool:
    return classify(algorithm).status is QuantumStatus.PQC


# ---------------------------------------------------------------------------
# CBOM
# ---------------------------------------------------------------------------
@dataclass
class CBOMEntry:
    """One algorithm's aggregated presence in the repository."""

    algorithm: str
    classification: AlgorithmClass
    occurrences: int = 0
    files: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "occurrences": self.occurrences,
            "files": self.files[:50],
            "operations": sorted(set(self.operations)),
            "languages": sorted(set(self.languages)),
            "evidence_ids": self.evidence_ids[:50],
            **self.classification.to_dict(),
        }


@dataclass
class CBOM:
    """Cryptographic Bill of Materials for a repository."""

    target: str
    entries: list[CBOMEntry] = field(default_factory=list)
    files_analyzed: int = 0
    unresolved_call_sites: int = 0
    #: crypto libraries imported / declared but with no resolved call site.
    #: Tracked separately: a library import is not an algorithm usage, and
    #: folding it into the algorithm inventory would inflate every count.
    dependencies: list[dict] = field(default_factory=list)
    #: Layer C output — contextual reasoning about purpose and migration
    #: urgency. Empty when no model was consulted; the CBOM itself is
    #: entirely deterministic either way.
    contextual_analysis: dict = field(default_factory=dict)

    # -- derived views ---------------------------------------------------
    def by_status(self) -> dict[str, list[CBOMEntry]]:
        out: dict[str, list[CBOMEntry]] = {}
        for entry in self.entries:
            out.setdefault(entry.classification.status.value, []).append(entry)
        return out

    @property
    def quantum_vulnerable(self) -> list[CBOMEntry]:
        return [e for e in self.entries
                if e.classification.status is QuantumStatus.VULNERABLE]

    @property
    def post_quantum(self) -> list[CBOMEntry]:
        return [e for e in self.entries if e.classification.status is QuantumStatus.PQC]

    @property
    def total_occurrences(self) -> int:
        return sum(e.occurrences for e in self.entries)

    def readiness_score(self) -> float:
        """0-100. Deterministic and explainable, not a model output.

        Vulnerable and classically-broken usages carry the weight;
        PQC usage earns credit back. Weighted by occurrence share so a
        repository with one legacy RSA call is not scored like one built
        entirely on RSA.
        """
        total = self.total_occurrences
        if total == 0:
            return 100.0
        weights = {
            QuantumStatus.VULNERABLE: 1.0,
            QuantumStatus.BROKEN: 0.8,
            QuantumStatus.WEAKENED: 0.25,
            QuantumStatus.UNKNOWN: 0.35,
            QuantumStatus.SAFE: 0.0,
            QuantumStatus.PQC: -0.25,          # credit for having migrated
        }
        penalty = sum(weights.get(e.classification.status, 0.3) * e.occurrences
                      for e in self.entries)
        score = 100.0 * (1.0 - max(0.0, penalty) / total)
        return round(max(0.0, min(100.0, score)), 2)

    def to_dict(self) -> dict:
        by_status = {status: len(entries) for status, entries in self.by_status().items()}
        return {
            "target": self.target,
            "files_analyzed": self.files_analyzed,
            "readiness_score": self.readiness_score(),
            "total_algorithms": len(self.entries),
            "total_occurrences": self.total_occurrences,
            "unresolved_call_sites": self.unresolved_call_sites,
            "crypto_dependencies": self.dependencies,
            "contextual_analysis": self.contextual_analysis,
            "by_status": by_status,
            "entries": [e.to_dict() for e in
                        sorted(self.entries,
                               key=lambda e: (-_status_rank(e.classification.status),
                                              -e.occurrences))],
        }


def _status_rank(status: QuantumStatus) -> int:
    return {
        QuantumStatus.VULNERABLE: 5,
        QuantumStatus.BROKEN: 4,
        QuantumStatus.UNKNOWN: 3,
        QuantumStatus.WEAKENED: 2,
        QuantumStatus.SAFE: 1,
        QuantumStatus.PQC: 0,
    }.get(status, 0)


def build_cbom(evidence_items, target: str = "", files_analyzed: int = 0) -> CBOM:
    """Aggregate crypto Evidence into a CBOM.

    Input is any iterable of `guardian.evidence.models.Evidence`. Items of
    type CRYPTO_USAGE become algorithm entries; CRYPTO_DEPENDENCY items
    (library imports and manifest declarations) are listed separately —
    importing `cryptography` is not itself an algorithm usage, and
    counting it as one would distort both the inventory and the score.
    """
    from guardian.evidence.models import EvidenceType

    grouped: dict[str, CBOMEntry] = {}
    dependencies: list[dict] = []
    unresolved = 0

    for item in evidence_items:
        metadata = item.metadata or {}
        if item.type is EvidenceType.CRYPTO_DEPENDENCY:
            dependencies.append({
                "name": metadata.get("module") or metadata.get("package") or item.symbol,
                "file": item.file,
                "line": item.line,
                "language": item.language,
                "algorithm": metadata.get("algorithm", ""),
                "evidence_id": item.id,
            })
            continue
        if item.type is not EvidenceType.CRYPTO_USAGE:
            continue

        algorithm = metadata.get("algorithm") or ""
        if not algorithm or algorithm == "unknown":
            unresolved += 1
            algorithm = "unknown"
        entry = grouped.get(algorithm)
        if entry is None:
            entry = CBOMEntry(algorithm=algorithm, classification=classify(algorithm))
            grouped[algorithm] = entry
        entry.occurrences += 1
        if item.file and item.file not in entry.files:
            entry.files.append(item.file)
        operation = metadata.get("operation") or ""
        if operation:
            entry.operations.append(operation)
        if item.language:
            entry.languages.append(item.language)
        if item.id:
            entry.evidence_ids.append(item.id)

    return CBOM(target=target, entries=list(grouped.values()),
                files_analyzed=files_analyzed, unresolved_call_sites=unresolved,
                dependencies=dependencies)
