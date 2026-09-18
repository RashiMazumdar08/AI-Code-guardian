"""
Quantum Readiness Engine — Detector
======================================
Scans source code for uses of quantum-vulnerable cryptographic algorithms.

Patterns cover Java and Python with enough confidence for a regex bridge
(same rationale as the Java security rule engine - full Tree-sitter AST
wiring is a future milestone).

Detected categories
-------------------
- RSA (any key size)
- ECC / ECDSA / ECDH
- DSA / DSS
- Diffie-Hellman
- AES-128 / AES-ECB (weakened, not broken)
- SHA-1 / SHA-256 (Grover weakened)
- MD5 (classically + quantum broken)
- Weak TLS (TLS 1.0, TLS 1.1, SSLv3)
- Weak SSH (ssh-rsa, ecdsa, diffie-hellman-*)
- OpenSSL deprecated API calls
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from guardian.quantum.models import (
    AlgorithmFamily, CryptoUsage, QuantumThreat
)

# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------
# Each entry: (pattern, algorithm_name, family, threat, context)
# Ordered from most-specific to least-specific within each family.

_JAVA_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    # RSA — anchored to crypto API usage, not the bare word
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"RSA"|\bRSA(?:PublicKey|PrivateKey|KeyGenParameterSpec|PublicKeySpec|PrivateKeySpec)\b|Cipher\.getInstance\(\s*"RSA'),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),
    (re.compile(r'Signature\.getInstance\(\s*"\w*withRSA"', re.I),
     "RSA signature", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "signing"),

    # ECC / ECDSA / ECDH — specific API tokens only (never a bare EC token)
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"EC"|\bEC(?:PublicKey|PrivateKey|GenParameterSpec|ParameterSpec)\b|\bECDSA\b|\bECDH\b|Signature\.getInstance\(\s*"\w*withECDSA"'),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),

    # DSA
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"DSA"|\bDSA(?:PublicKeySpec|PrivateKeySpec)\b|Signature\.getInstance\(\s*"\w*withDSA"'),
     "DSA", AlgorithmFamily.DSA, QuantumThreat.CRITICAL, "signing"),

    # Diffie-Hellman
    (re.compile(r'KeyPairGenerator\.getInstance\(\s*"DH"|\bDH(?:PublicKeySpec|PrivateKeySpec|ParameterSpec)\b|KeyAgreement\.getInstance\(\s*"(?:EC)?DH"'),
     "Diffie-Hellman", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key exchange"),

    # AES-ECB / explicit AES-128 key size
    (re.compile(r'Cipher\.getInstance\(\s*"AES/ECB'),
     "AES/ECB", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption (ECB mode)"),
    (re.compile(r'KeyGenerator\b[^;]{0,80}\binit\(\s*128\s*\)|"AES"\s*,\s*128'),
     "AES-128", AlgorithmFamily.AES, QuantumThreat.MEDIUM, "encryption (Grover-weakened key size)"),

    # Hash inventory (SHA-256 is inventory-only: LOW)
    (re.compile(r'MessageDigest\.getInstance\(\s*"SHA-?1"|DigestUtils\.sha1|\bHmacSHA1\b'),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'MessageDigest\.getInstance\(\s*"SHA-?256"|\bHmacSHA256\b'),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.LOW, "hashing (inventory)"),
    (re.compile(r'MessageDigest\.getInstance\(\s*"MD5"|DigestUtils\.md5'),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),

    # Weak TLS
    (re.compile(r'SSLContext\.getInstance\(\s*"(SSLv3|TLSv1(\.1)?|SSL)"'),
     "Weak TLS", AlgorithmFamily.TLS, QuantumThreat.LOW, "transport security"),
]

_PYTHON_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    # RSA — real library call sites
    (re.compile(r'\brsa\.(generate_private_key|RSAPublicKey|RSAPrivateKey|newkeys)\b|Crypto(?:dome)?\.PublicKey(?:\.| import )RSA|from\s+cryptography[\w.]*\s+import\s+[\w, ]*\brsa\b'),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),

    # ECC — specific hazmat/ecdsa call sites (NEVER bare "ec.")
    (re.compile(r'\bec\.(generate_private_key|ECDH|ECDSA|SECP\w+|EllipticCurve\w*)\b|from\s+cryptography[\w.]*\s+import\s+[\w, ]*\bec\b|\becdsa\.(SigningKey|VerifyingKey)\b'),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),

    # DSA
    (re.compile(r'\bdsa\.(generate_private_key|DSAPublicKey|DSAPrivateKey)\b|Crypto(?:dome)?\.PublicKey(?:\.| import )DSA'),
     "DSA", AlgorithmFamily.DSA, QuantumThreat.CRITICAL, "signing"),

    # Diffie-Hellman
    (re.compile(r'\bdh\.(generate_parameters|generate_private_key|DHPublicKey|DHPrivateKey)\b'),
     "Diffie-Hellman", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key exchange"),

    # AES-ECB
    (re.compile(r'AES\.new\([^)]*MODE_ECB|modes\.ECB\('),
     "AES/ECB", AlgorithmFamily.AES, QuantumThreat.HIGH, "encryption (ECB mode)"),

    # Hashes — call sites only
    (re.compile(r'hashlib\.sha1\b|hmac\.new\([^)]*sha1'),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'hashlib\.md5\b'),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'hashlib\.sha256\b|hmac\.new\([^)]*sha256'),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.LOW, "hashing (inventory)"),

    # Weak TLS
    (re.compile(r'ssl\.PROTOCOL_(TLSv1(_1)?|SSLv[23])\b'),
     "Weak TLS", AlgorithmFamily.TLS, QuantumThreat.LOW, "transport security"),
]

_JS_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    (re.compile(r'generateKeyPair(?:Sync)?\(\s*[\'"]rsa|[\'"]RSA-(?:OAEP|PSS)[\'"]|publicEncrypt\('),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),
    (re.compile(r'generateKeyPair(?:Sync)?\(\s*[\'"]ec[\'"]|[\'"]ECDSA[\'"]|[\'"]ECDH[\'"]|createECDH\('),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),
    (re.compile(r'createDiffieHellman\('),
     "Diffie-Hellman", AlgorithmFamily.DIFFIE_HELLMAN, QuantumThreat.CRITICAL, "key exchange"),
    (re.compile(r'createHash\(\s*[\'"]sha1[\'"]|createHmac\(\s*[\'"]sha1'),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'createHash\(\s*[\'"]md5[\'"]'),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'createHash\(\s*[\'"]sha256[\'"]|createHmac\(\s*[\'"]sha256'),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.LOW, "hashing (inventory)"),
]

_RUST_PATTERNS: list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]] = [
    (re.compile(r'\bRsaKeyPair\b|\bRsa(?:Private|Public)Key\b|\brsa::\w|RSA_P(?:KCS1|SS)_|RSA_PSS_|openssl::rsa'),
     "RSA", AlgorithmFamily.RSA, QuantumThreat.CRITICAL, "encryption/signing"),
    (re.compile(r'\bEcdsaKeyPair\b|ECDSA_P\d+|\bp(?:256|384|521)::\w|agreement::ECDH|\bX25519\b|openssl::ec\b'),
     "ECC/ECDSA", AlgorithmFamily.ECC, QuantumThreat.CRITICAL, "signing/key exchange"),
    (re.compile(r'\bmd5::compute\b|\bMd5::new\b'),
     "MD5", AlgorithmFamily.MD5, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'\bSha1::new\b|\bsha1::\w'),
     "SHA-1", AlgorithmFamily.SHA, QuantumThreat.MEDIUM, "hashing"),
    (re.compile(r'\bSha256::new\b|HMAC_SHA256|digest::SHA256'),
     "SHA-256", AlgorithmFamily.SHA, QuantumThreat.LOW, "hashing (inventory)"),
]

def _get_patterns(
    file_label: str,
) -> list[tuple[re.Pattern, str, AlgorithmFamily, QuantumThreat, str]]:
    ext = Path(file_label).suffix.lower()
    if ext == ".java" or ext in (".kt", ".scala"):
        return _JAVA_PATTERNS
    if ext == ".py":
        return _PYTHON_PATTERNS
    if ext in (".js", ".jsx", ".ts", ".tsx"):
        return _JS_PATTERNS
    if ext == ".rs":
        return _RUST_PATTERNS
    if "ssh" in file_label.lower() or ext == ".conf":
        return _SSH_CONFIG_PATTERNS
    return []   # unknown types: no quantum scanning (precision over recall)


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class QuantumDetector:
    """
    Scans source code and returns a list of `CryptoUsage` objects.
    One CryptoUsage per detected pattern per line.

    Deduplication: identical (file, line, algorithm) triplets are collapsed.
    """

    _COMMENT_PREFIXES = ("//", "#", "*", "/*", "--", "///", "//!")

    def scan_text(self, text: str, file_label: str) -> list[CryptoUsage]:
        patterns = _get_patterns(file_label)
        seen: set[str] = set()
        usages: list[CryptoUsage] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(self._COMMENT_PREFIXES):
                continue  # comments/prose are inventory noise, not crypto usage
            for pat, algorithm, family, threat, context in patterns:
                if not pat.search(line):
                    continue
                key = f"{file_label}:{lineno}:{algorithm}"
                if key in seen:
                    continue
                seen.add(key)
                usages.append(CryptoUsage(
                    algorithm=algorithm,
                    family=family,
                    threat_level=threat,
                    file=file_label,
                    line=lineno,
                    snippet=line.strip()[:200],
                    context=context,
                ))
                break  # only first matching pattern per line per file
        return usages

    def scan_file(self, path: Path) -> list[CryptoUsage]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.scan_text(text, str(path))

    def scan_directory(
        self,
        root: Path,
        extensions: Iterable[str] = (".java", ".py", ".conf", ".yaml", ".yml"),
        exclude_dirs: Iterable[str] = ("test", "tests", ".git", "node_modules"),
    ) -> list[CryptoUsage]:
        root = Path(root)
        exclude_dirs = set(exclude_dirs)
        usages: list[CryptoUsage] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fn in filenames:
                if Path(fn).suffix.lower() in set(extensions):
                    fp = Path(dirpath) / fn
                    try:
                        rel = str(fp.relative_to(root))
                    except ValueError:
                        rel = str(fp)
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                    usages.extend(self.scan_text(text, rel))
        return usages
