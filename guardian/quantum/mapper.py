"""
Quantum Readiness Engine — Migration Mapper
=============================================
Maps vulnerable algorithms to NIST PQC replacements.

To update for future NIST PQC revisions: edit MIGRATION_MAP only.
All other code uses the returned MigrationRecommendation objects,
so callers are insulated from standard changes.
"""
from __future__ import annotations

from guardian.quantum.models import AlgorithmFamily, MigrationRecommendation, QuantumThreat

# ---------------------------------------------------------------------------
# NIST PQC Migration Map (FIPS 203/204/205, August 2024)
# ---------------------------------------------------------------------------
# Key: (AlgorithmFamily, QuantumThreat) — most-specific match wins.
# Value: MigrationRecommendation constructor kwargs.

MIGRATION_MAP: dict[str, dict] = {
    "RSA": {
        "replacement_algorithm": "ML-KEM (CRYSTALS-Kyber) for encryption; ML-DSA (CRYSTALS-Dilithium) for signing",
        "nist_standard": "FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)",
        "rationale": "RSA is broken by Shor's Algorithm on a cryptographically relevant quantum computer. "
                     "ML-KEM provides quantum-safe key encapsulation; ML-DSA provides quantum-safe digital signatures.",
        "migration_effort": "High",
        "example_code": (
            "# Python (oqs-python / liboqs)\n"
            "from oqs import KeyEncapsulation, Signature\n"
            "# Encryption replacement:\n"
            "kem = KeyEncapsulation('Kyber768')\n"
            "public_key, secret_key = kem.generate_keypair()\n"
            "ciphertext, shared_secret = kem.encap_secret(public_key)\n"
            "# Signing replacement:\n"
            "signer = Signature('Dilithium3')\n"
            "pub, priv = signer.generate_keypair()\n"
            "signature = signer.sign(message, priv)"
        ),
        "references": ["https://doi.org/10.6028/NIST.FIPS.203", "https://doi.org/10.6028/NIST.FIPS.204"],
    },
    "ECC": {
        "replacement_algorithm": "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
        "nist_standard": "FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)",
        "rationale": "ECDSA/ECDH rely on the elliptic curve discrete log problem, which Shor's Algorithm solves efficiently.",
        "migration_effort": "High",
        "example_code": (
            "from oqs import Signature\n"
            "signer = Signature('Dilithium3')  # or 'SPHINCS+-SHA2-128s'\n"
            "public_key, secret_key = signer.generate_keypair()\n"
            "signature = signer.sign(message, secret_key)"
        ),
        "references": ["https://doi.org/10.6028/NIST.FIPS.204", "https://doi.org/10.6028/NIST.FIPS.205"],
    },
    "DSA": {
        "replacement_algorithm": "ML-DSA (Dilithium)",
        "nist_standard": "FIPS 204 (ML-DSA)",
        "rationale": "DSA relies on the discrete log problem, vulnerable to Shor's Algorithm.",
        "migration_effort": "Medium",
        "example_code": "# See RSA example above — use Dilithium3 from oqs-python.",
        "references": ["https://doi.org/10.6028/NIST.FIPS.204"],
    },
    "Diffie-Hellman": {
        "replacement_algorithm": "ML-KEM (Kyber) for key exchange",
        "nist_standard": "FIPS 203 (ML-KEM)",
        "rationale": "Diffie-Hellman key exchange relies on the discrete log problem, broken by Shor's Algorithm.",
        "migration_effort": "High",
        "example_code": (
            "# Hybrid TLS with ECDHE + ML-KEM (draft RFC support in TLS 1.3)\n"
            "# For Java: use Bouncy Castle PQC provider with CRYSTALS-Kyber\n"
            "# For Python: oqs-python KeyEncapsulation('Kyber768')"
        ),
        "references": ["https://doi.org/10.6028/NIST.FIPS.203"],
    },
    "AES-128": {
        "replacement_algorithm": "AES-256",
        "nist_standard": "NIST SP 800-175Br1",
        "rationale": "Grover's Algorithm halves the effective key strength, reducing AES-128 to ~64 bits. AES-256 provides sufficient post-quantum security.",
        "migration_effort": "Low",
        "example_code": (
            "# Java\n"
            'KeyGenerator kg = KeyGenerator.getInstance("AES");\n'
            "kg.init(256);\n"
            "# Python\n"
            "from Crypto.Cipher import AES\n"
            "key = os.urandom(32)  # 256 bits"
        ),
        "references": ["https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final"],
    },
    "AES/ECB": {
        "replacement_algorithm": "AES-256-GCM (authenticated encryption)",
        "nist_standard": "NIST SP 800-38D",
        "rationale": "ECB mode is deterministic and reveals data patterns. Replace with GCM for authenticated encryption.",
        "migration_effort": "Low",
        "example_code": (
            "# Java\n"
            'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
            "# Python\n"
            "from Crypto.Cipher import AES\n"
            "cipher = AES.new(key, AES.MODE_GCM)"
        ),
        "references": [],
    },
    "SHA-1": {
        "replacement_algorithm": "SHA-384 or SHA3-256",
        "nist_standard": "NIST SP 800-107r1",
        "rationale": "SHA-1 is classically broken (collision attacks). Grover's Algorithm further weakens it. NIST deprecated SHA-1 for all applications.",
        "migration_effort": "Low",
        "example_code": (
            "# Java\n"
            'MessageDigest md = MessageDigest.getInstance("SHA-384");\n'
            "# Python\n"
            "import hashlib; h = hashlib.sha384(data).hexdigest()"
        ),
        "references": [],
    },
    "SHA-256": {
        "replacement_algorithm": "SHA-384 or SHA3-256",
        "nist_standard": "NIST SP 800-107r1",
        "rationale": "Grover's Algorithm reduces SHA-256 collision resistance to ~128 bits. SHA-384/SHA3-256 provide adequate post-quantum margins.",
        "migration_effort": "Low",
        "example_code": "import hashlib; h = hashlib.sha384(data).hexdigest()",
        "references": [],
    },
    "MD5": {
        "replacement_algorithm": "SHA-256 minimum; SHA-384 recommended",
        "nist_standard": "NIST SP 800-107r1",
        "rationale": "MD5 is classically broken for collision resistance. Quantum computing further weakens it. Never use for security purposes.",
        "migration_effort": "Low",
        "example_code": "import hashlib; h = hashlib.sha256(data).hexdigest()",
        "references": [],
    },
    "Weak TLS": {
        "replacement_algorithm": "TLS 1.3 with hybrid PQC key exchange",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "TLS 1.0/1.1/SSLv3 are deprecated and vulnerable. Upgrade to TLS 1.3 with X25519Kyber768 draft hybrid KEX for quantum safety.",
        "migration_effort": "Medium",
        "example_code": (
            "# Java: configure SSLContext for TLS 1.3\n"
            'SSLContext ctx = SSLContext.getInstance("TLSv1.3");\n'
            "# Python\n"
            "ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
            "ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3"
        ),
        "references": ["https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"],
    },
    "Weak SSH": {
        "replacement_algorithm": "ssh-ed25519 keys; ecdh-sha2-nistp256 KEX → ML-KEM hybrid",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "ssh-rsa and diffie-hellman-group1 are deprecated. Use ed25519 for host keys and a PQC-hybrid KEX when available.",
        "migration_effort": "Medium",
        "example_code": "# sshd_config\nHostKeyAlgorithms ssh-ed25519\nKexAlgorithms curve25519-sha256",
        "references": [],
    },
    "Legacy SSL": {
        "replacement_algorithm": "TLS 1.3",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "Legacy SSL/TLS versions are deprecated and vulnerable.",
        "migration_effort": "Low",
        "example_code": 'SSLContext ctx = SSLContext.getInstance("TLSv1.3");',
        "references": [],
    },
    "SSH RSA key": {
        "replacement_algorithm": "ssh-ed25519 host keys",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "RSA-based SSH keys are vulnerable to Shor's Algorithm.",
        "migration_effort": "Medium",
        "example_code": "# sshd_config: HostKeyAlgorithms ssh-ed25519",
        "references": [],
    },
    "SSH Diffie-Hellman KEX": {
        "replacement_algorithm": "curve25519-sha256 or sntrup761x25519-sha512",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "DH-based SSH key exchange is vulnerable to Shor's Algorithm.",
        "migration_effort": "Low",
        "example_code": "# sshd_config: KexAlgorithms curve25519-sha256,sntrup761x25519-sha512@openssh.com",
        "references": [],
    },
    "SSH weak cipher": {
        "replacement_algorithm": "chacha20-poly1305 or aes256-gcm",
        "nist_standard": "NIST SP 800-52r2",
        "rationale": "arcfour/3DES are deprecated ciphers.",
        "migration_effort": "Low",
        "example_code": "# sshd_config: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "references": [],
    },
}


class MigrationMapper:
    """
    Looks up the NIST PQC migration recommendation for a detected algorithm.
    Returns None if no mapping is defined (treated as quantum-safe).

    To support future NIST PQC updates: edit MIGRATION_MAP above.
    The mapper class and all callers are unchanged.
    """

    def __init__(self, migration_map: dict | None = None):
        self._map = migration_map if migration_map is not None else MIGRATION_MAP

    def get_recommendation(self, algorithm: str) -> MigrationRecommendation | None:
        # Try exact match first, then partial-name match
        entry = self._map.get(algorithm)
        if entry is None:
            for key in self._map:
                if key.lower() in algorithm.lower() or algorithm.lower() in key.lower():
                    entry = self._map[key]
                    break
        if entry is None:
            return None
        return MigrationRecommendation(
            vulnerable_algorithm=algorithm,
            **entry,
        )

    def map_usages(self, usages) -> list[MigrationRecommendation]:
        seen: set[str] = set()
        recs: list[MigrationRecommendation] = []
        for u in usages:
            if u.algorithm in seen:
                continue
            rec = self.get_recommendation(u.algorithm)
            if rec:
                seen.add(u.algorithm)
                recs.append(rec)
        return recs
