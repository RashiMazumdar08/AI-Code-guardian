"""
UST Semantic Tagging
====================
Turns structural UST nodes into *semantically* meaningful ones by
recognising well-known API shapes across languages:

    crypto_tags     RSA / ECC / AES / hashing / TLS / KEM / signatures
    security_tags   taint sources, dangerous sinks, sanitisers, secrets
    business_tags   authorization checks, API endpoints, DB operations,
                    entry points, money/PII vocabulary

Matching happens on the *symbol* (a normalised dotted callee such as
`Cipher.getInstance` or `hashlib.md5`), on import statements, and on
string literal arguments (`Cipher.getInstance("AES/ECB/PKCS5Padding")`).
That is deliberately stronger than keyword matching over raw lines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from guardian.ust.models import USTFile, USTNode, USTNodeType

# ---------------------------------------------------------------------------
# Crypto catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CryptoSignature:
    """A recognised cryptographic API.

    `symbols` are matched against the tail of a UST symbol, so
    `javax.crypto.Cipher.getInstance` and `Cipher.getInstance` both hit
    the `Cipher.getInstance` signature.
    """

    symbols: tuple[str, ...]
    operation: str                     # encryption / hashing / signing / key_exchange / ...
    algorithm: str = ""                # fixed algorithm, when the API implies one
    from_literal: bool = False         # algorithm comes from a string argument
    languages: tuple[str, ...] = ()    # empty = all languages


#: Algorithm names recognised inside string arguments and API names.
#: Order matters: longer/more specific names are checked first.
ALGORITHM_ALIASES: list[tuple[re.Pattern, str]] = [
    # PQC parameter sets carry a trailing strength digit (Kyber768,
    # Dilithium3, ML-KEM-1024) — the alias must absorb it.
    (re.compile(r"\bml[-_]?kem\b|\bkyber\d*\b|\bcrystals[-_]kyber\d*\b", re.I), "ML-KEM"),
    (re.compile(r"\bml[-_]?dsa\b|\bdilithium\d*\b|\bcrystals[-_]dilithium\d*\b", re.I), "ML-DSA"),
    (re.compile(r"\bslh[-_]?dsa\b|\bsphincs\+?\b", re.I), "SLH-DSA"),
    (re.compile(r"\bfalcon\d*\b", re.I), "FN-DSA"),
    (re.compile(r"\bntru\w*\b|\bsntrup\d*\b", re.I), "NTRU"),
    (re.compile(r"\bfrodo(?:kem)?\d*\b", re.I), "FrodoKEM"),
    (re.compile(r"\bhqc\b|\bbike\b|\bclassic[-_ ]?mceliece\b", re.I), "PQC-KEM"),
    (re.compile(r"\becdsa\b", re.I), "ECDSA"),
    (re.compile(r"\becdh\b", re.I), "ECDH"),
    (re.compile(r"\bed25519\b", re.I), "Ed25519"),
    (re.compile(r"\bx25519\b|\bcurve25519\b", re.I), "X25519"),
    (re.compile(r"\bsecp\d+[rk]?\d*\b|\bprime256v1\b|\bnistp(?:256|384|521)\b|\bp-?(?:256|384|521)\b", re.I), "ECC"),
    (re.compile(r"\brsassa\b|\brsa[-_]?(?:oaep|pss|pkcs1)\b|\brsa\b", re.I), "RSA"),
    (re.compile(r"\bdsa\b|\bdss\b", re.I), "DSA"),
    (re.compile(r"\bdiffie[-_ ]?hellman\b|\bdhke\b|(?<![a-z])dh(?![a-z])", re.I), "DH"),
    (re.compile(r"\b3des\b|\btriple[-_ ]?des\b|\bdesede\b", re.I), "3DES"),
    (re.compile(r"\bdes\b", re.I), "DES"),
    (re.compile(r"\brc4\b|\barcfour\b", re.I), "RC4"),
    (re.compile(r"\bchacha20\b|\bpoly1305\b", re.I), "ChaCha20"),
    (re.compile(r"\baes[-_]?256\b", re.I), "AES-256"),
    (re.compile(r"\baes[-_]?192\b", re.I), "AES-192"),
    (re.compile(r"\baes[-_]?128\b", re.I), "AES-128"),
    (re.compile(r"\baes\b", re.I), "AES"),
    (re.compile(r"\bblowfish\b", re.I), "Blowfish"),
    (re.compile(r"\bsha3[-_]?(?:256|384|512)\b|\bsha[-_]?3\b", re.I), "SHA-3"),
    (re.compile(r"\bsha[-_]?512\b", re.I), "SHA-512"),
    (re.compile(r"\bsha[-_]?384\b", re.I), "SHA-384"),
    (re.compile(r"\bsha[-_]?256\b", re.I), "SHA-256"),
    (re.compile(r"\bsha[-_]?224\b", re.I), "SHA-224"),
    (re.compile(r"\bsha[-_]?1\b|\bsha1\b", re.I), "SHA-1"),
    (re.compile(r"\bmd5\b", re.I), "MD5"),
    (re.compile(r"\bmd4\b", re.I), "MD4"),
    (re.compile(r"\bblake2[bs]?\b", re.I), "BLAKE2"),
    (re.compile(r"\bargon2(?:id|i|d)?\b", re.I), "Argon2"),
    (re.compile(r"\bbcrypt\b", re.I), "bcrypt"),
    (re.compile(r"\bscrypt\b", re.I), "scrypt"),
    (re.compile(r"\bpbkdf2\b", re.I), "PBKDF2"),
    (re.compile(r"\bsslv[23]\b", re.I), "SSLv3"),
    (re.compile(r"\btls\s*v?1\.3\b|\btlsv1_3\b", re.I), "TLS1.3"),
    (re.compile(r"\btls\s*v?1\.2\b|\btlsv1_2\b", re.I), "TLS1.2"),
    (re.compile(r"\btls\s*v?1\.[01]\b|\btlsv1(?:_1)?\b", re.I), "TLS1.0/1.1"),
]

#: Cipher-mode markers worth surfacing even when the algorithm is known.
MODE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/ECB/|\bMODE_ECB\b|\bECB\b", re.I), "ECB"),
    (re.compile(r"/CBC/|\bMODE_CBC\b", re.I), "CBC"),
    (re.compile(r"/GCM/|\bMODE_GCM\b", re.I), "GCM"),
    (re.compile(r"/CTR/|\bMODE_CTR\b", re.I), "CTR"),
]

CRYPTO_SIGNATURES: list[CryptoSignature] = [
    # ---- Java / JVM -------------------------------------------------
    CryptoSignature(("Cipher.getInstance",), "encryption", from_literal=True, languages=("java",)),
    CryptoSignature(("KeyGenerator.getInstance", "KeyPairGenerator.getInstance",
                     "KeyFactory.getInstance", "SecretKeyFactory.getInstance"),
                    "key_generation", from_literal=True, languages=("java",)),
    CryptoSignature(("Signature.getInstance",), "signing", from_literal=True, languages=("java",)),
    CryptoSignature(("MessageDigest.getInstance",), "hashing", from_literal=True, languages=("java",)),
    CryptoSignature(("Mac.getInstance",), "mac", from_literal=True, languages=("java",)),
    CryptoSignature(("KeyAgreement.getInstance",), "key_exchange", from_literal=True, languages=("java",)),
    CryptoSignature(("SSLContext.getInstance",), "tls", from_literal=True, languages=("java",)),
    CryptoSignature(("CertificateFactory.getInstance", "TrustManagerFactory.getInstance"),
                    "certificate", from_literal=True, languages=("java",)),
    CryptoSignature(("SecureRandom.getInstance",), "random", from_literal=True, languages=("java",)),
    CryptoSignature(("DigestUtils.md5Hex", "DigestUtils.md5"), "hashing", "MD5", languages=("java",)),
    CryptoSignature(("DigestUtils.sha1Hex", "DigestUtils.sha1"), "hashing", "SHA-1", languages=("java",)),
    CryptoSignature(("DigestUtils.sha256Hex", "DigestUtils.sha256"), "hashing", "SHA-256", languages=("java",)),

    # ---- Python ------------------------------------------------------
    CryptoSignature(("hashlib.md5",), "hashing", "MD5", languages=("python",)),
    CryptoSignature(("hashlib.sha1",), "hashing", "SHA-1", languages=("python",)),
    CryptoSignature(("hashlib.sha224",), "hashing", "SHA-224", languages=("python",)),
    CryptoSignature(("hashlib.sha256",), "hashing", "SHA-256", languages=("python",)),
    CryptoSignature(("hashlib.sha384",), "hashing", "SHA-384", languages=("python",)),
    CryptoSignature(("hashlib.sha512",), "hashing", "SHA-512", languages=("python",)),
    CryptoSignature(("hashlib.sha3_256", "hashlib.sha3_512"), "hashing", "SHA-3", languages=("python",)),
    CryptoSignature(("hashlib.new",), "hashing", from_literal=True, languages=("python",)),
    CryptoSignature(("hashlib.pbkdf2_hmac",), "key_derivation", "PBKDF2", languages=("python",)),
    CryptoSignature(("hmac.new",), "mac", from_literal=True, languages=("python",)),
    CryptoSignature(("rsa.generate_private_key", "RSA.generate", "rsa.newkeys",
                     "RSA.construct", "rsa.RSAPrivateKey", "rsa.RSAPublicKey"),
                    "key_generation", "RSA", languages=("python",)),
    CryptoSignature(("padding.OAEP", "padding.PSS", "padding.PKCS1v15"),
                    "encryption", "RSA", languages=("python",)),
    CryptoSignature(("ec.generate_private_key", "ec.derive_private_key", "ECC.generate"),
                    "key_generation", "ECC", languages=("python",)),
    CryptoSignature(("ec.ECDSA", "ecdsa.SigningKey", "ecdsa.VerifyingKey",
                     "DSS.new"), "signing", "ECDSA", languages=("python",)),
    CryptoSignature(("ec.ECDH",), "key_exchange", "ECDH", languages=("python",)),
    CryptoSignature(("dsa.generate_private_key", "DSA.generate"),
                    "key_generation", "DSA", languages=("python",)),
    CryptoSignature(("dh.generate_parameters", "dh.generate_private_key"),
                    "key_exchange", "DH", languages=("python",)),
    CryptoSignature(("AES.new",), "encryption", "AES", languages=("python",)),
    CryptoSignature(("DES.new", "DES3.new"), "encryption", from_literal=False,
                    languages=("python",)),
    CryptoSignature(("Cipher", "algorithms.AES", "algorithms.TripleDES",
                     "algorithms.Blowfish", "algorithms.ARC4"),
                    "encryption", from_literal=True, languages=("python",)),
    CryptoSignature(("Fernet", "Fernet.generate_key"), "encryption", "AES-128", languages=("python",)),
    CryptoSignature(("ssl.SSLContext", "ssl.wrap_socket", "ssl.create_default_context"),
                    "tls", from_literal=True, languages=("python",)),
    CryptoSignature(("jwt.encode", "jwt.decode"), "signing", from_literal=True, languages=("python",)),
    CryptoSignature(("KeyEncapsulation", "oqs.KeyEncapsulation"), "kem",
                    from_literal=True, languages=("python",)),
    CryptoSignature(("oqs.Signature",), "signing", from_literal=True, languages=("python",)),

    # ---- JavaScript / TypeScript ------------------------------------
    CryptoSignature(("crypto.createHash", "createHash"), "hashing",
                    from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("crypto.createHmac", "createHmac"), "mac",
                    from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("crypto.createCipheriv", "crypto.createDecipheriv",
                     "crypto.createCipher", "createCipheriv"), "encryption",
                    from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("crypto.generateKeyPair", "crypto.generateKeyPairSync",
                     "generateKeyPair", "generateKeyPairSync"), "key_generation",
                    from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("crypto.publicEncrypt", "crypto.privateDecrypt"), "encryption",
                    "RSA", languages=("javascript", "typescript")),
    CryptoSignature(("crypto.createSign", "crypto.createVerify"), "signing",
                    from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("crypto.createDiffieHellman", "createDiffieHellman"),
                    "key_exchange", "DH", languages=("javascript", "typescript")),
    CryptoSignature(("crypto.createECDH", "createECDH"), "key_exchange", "ECDH",
                    languages=("javascript", "typescript")),
    CryptoSignature(("subtle.encrypt", "subtle.decrypt", "subtle.generateKey",
                     "subtle.sign", "subtle.verify", "subtle.deriveKey",
                     "crypto.subtle.encrypt", "crypto.subtle.generateKey"),
                    "encryption", from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("bcrypt.hash", "bcrypt.hashSync"), "key_derivation", "bcrypt",
                    languages=("javascript", "typescript")),
    CryptoSignature(("https.createServer", "tls.createServer", "tls.connect"),
                    "tls", from_literal=True, languages=("javascript", "typescript")),
    CryptoSignature(("jsonwebtoken.sign", "jwt.sign", "jwt.verify"), "signing",
                    from_literal=True, languages=("javascript", "typescript")),

    # ---- Rust ---------------------------------------------------------
    CryptoSignature(("RsaPrivateKey.new", "RsaPublicKey.new", "RsaKeyPair.from_pkcs8",
                     "RsaKeyPair.from_der", "Rsa.generate", "openssl.rsa.Rsa.generate"),
                    "key_generation", "RSA", languages=("rust",)),
    CryptoSignature(("EcdsaKeyPair.from_pkcs8", "SigningKey.random", "p256.ecdsa",
                     "p384.ecdsa"), "signing", "ECDSA", languages=("rust",)),
    CryptoSignature(("agreement.agree_ephemeral", "EphemeralPrivateKey.generate"),
                    "key_exchange", "ECDH", languages=("rust",)),
    CryptoSignature(("Md5.new", "md5.compute", "Md5.digest"), "hashing", "MD5",
                    languages=("rust",)),
    CryptoSignature(("Sha1.new", "sha1.digest"), "hashing", "SHA-1", languages=("rust",)),
    CryptoSignature(("Sha256.new", "Sha256.digest", "digest.digest"), "hashing",
                    "SHA-256", languages=("rust",)),
    CryptoSignature(("Sha512.new",), "hashing", "SHA-512", languages=("rust",)),
    CryptoSignature(("Aes128Gcm.new", "Aes256Gcm.new", "Aes256.new", "Aes128.new"),
                    "encryption", from_literal=False, languages=("rust",)),
    CryptoSignature(("argon2.hash_password", "Argon2.new"), "key_derivation", "Argon2",
                    languages=("rust",)),
    CryptoSignature(("SystemRandom.new", "OsRng.fill_bytes", "thread_rng"), "random",
                    languages=("rust",)),
    CryptoSignature(("danger_accept_invalid_certs", "danger_accept_invalid_hostnames"),
                    "tls", languages=("rust",)),
    CryptoSignature(("ClientConfig.builder", "ServerConfig.builder", "SslConnector.builder"),
                    "tls", from_literal=True, languages=("rust",)),
]

#: Imports that establish a file as crypto-relevant even without a call site.
CRYPTO_IMPORT_HINTS = re.compile(
    r"(?i)\b(javax\.crypto|java\.security|bouncycastle|bcprov|cryptography|"
    r"Crypto(?:dome)?\.|hashlib|hmac|nacl|pynacl|oqs|liboqs|ring|rustls|openssl|"
    r"rsa|ecdsa|ed25519|node:crypto|crypto-js|jsonwebtoken|bcrypt|argon2|sodium)\b")


def resolve_algorithm(text: str) -> str:
    """Extract a canonical algorithm name from an API name or literal."""
    for pattern, name in ALGORITHM_ALIASES:
        if pattern.search(text):
            return name
    return ""


def resolve_mode(text: str) -> str:
    for pattern, name in MODE_PATTERNS:
        if pattern.search(text):
            return name
    return ""


def _match_signature(node: USTNode) -> Optional[CryptoSignature]:
    symbol = node.symbol or node.name
    if not symbol:
        return None
    lowered = symbol.lower()
    for sig in CRYPTO_SIGNATURES:
        if sig.languages and node.language not in sig.languages:
            continue
        for candidate in sig.symbols:
            cand = candidate.lower()
            if lowered == cand or lowered.endswith("." + cand) or cand in lowered.split("."):
                return sig
    return None


def crypto_tags_for(node: USTNode) -> list[str]:
    """Crypto tags for one node, or [] when it is not a crypto operation."""
    sig = _match_signature(node)
    if sig is None:
        return []

    algorithm = sig.algorithm
    mode = ""
    if sig.from_literal or not algorithm:
        for literal in node.literals:
            found = resolve_algorithm(literal)
            if found:
                algorithm = found
                mode = mode or resolve_mode(literal)
                break
        if not algorithm:
            # try the API name itself (e.g. `DES3.new`, `Aes256Gcm.new`)
            algorithm = resolve_algorithm(node.symbol or node.name)
    if not mode:
        mode = resolve_mode(" ".join(node.literals) or node.symbol)

    tags = ["crypto", f"operation:{sig.operation}"]
    tags.append(f"algorithm:{algorithm or 'unknown'}")
    if mode:
        tags.append(f"mode:{mode}")
    if not algorithm and not sig.from_literal:
        tags.append("algorithm_unresolved")
    elif not algorithm:
        tags.append("algorithm_unresolved")
    return tags


# ---------------------------------------------------------------------------
# Security tagging
# ---------------------------------------------------------------------------
TAINT_SOURCES = re.compile(
    r"(?i)(^|\.)(input|raw_input|getenv|environ\.get|"
    r"request\.(args|form|json|values|body|params|query|get_json|GET|POST)|"
    r"req\.(body|query|params|headers)|"
    r"getParameter|getHeader|getQueryString|getInputStream|getReader|"
    r"readLine|argv|stdin|read_to_string|from_utf8|"
    r"query_params|path_params|body_bytes)(\.|$)")

SQL_SINKS = re.compile(
    r"(?i)(^|\.)(execute|executemany|executescript|executeQuery|executeUpdate|"
    r"executeBatch|createQuery|createNativeQuery|raw|rawQuery|query|"
    r"fetch_one|fetch_all|fetch_optional|find|aggregate)(\.|$)")

COMMAND_SINKS = re.compile(
    r"(?i)(^|\.)(system|popen|spawn|spawnSync|exec|execSync|execFile|call|run|"
    r"check_output|check_call|getRuntime|Runtime\.exec|ProcessBuilder|"
    r"Command\.new|child_process\.exec)(\.|$)")

EVAL_SINKS = re.compile(r"(?i)(^|\.)(eval|exec|Function|compile|vm\.runInNewContext)(\.|$)")

DESERIALIZATION_SINKS = re.compile(
    r"(?i)(^|\.)(loads?|load|readObject|ObjectInputStream|from_str|from_slice|"
    r"unpickle|yaml\.load|deserialize|parse)(\.|$)")

FILE_SINKS = re.compile(
    r"(?i)(^|\.)(open|readFile|readFileSync|createReadStream|read_to_string|"
    r"File\.new|Files\.readAllBytes|Paths\.get|sendFile)(\.|$)")

SANITIZERS = re.compile(
    r"(?i)(^|\.)(escape|quote|sanitize|sanitise|encode|htmlspecialchars|"
    r"parameterize|bind|validator|clean|strip_tags|parseInt|parse_int|"
    r"escapeHtml|encodeURIComponent)(\.|$)")

SINK_KINDS: list[tuple[re.Pattern, str]] = [
    (SQL_SINKS, "sink:sql"),
    (COMMAND_SINKS, "sink:command"),
    (EVAL_SINKS, "sink:eval"),
    (DESERIALIZATION_SINKS, "sink:deserialization"),
    (FILE_SINKS, "sink:file"),
]


def security_tags_for(node: USTNode) -> list[str]:
    symbol = node.symbol or node.name
    if not symbol:
        return []
    tags: list[str] = []
    if TAINT_SOURCES.search(symbol):
        tags.append("source")
    for pattern, tag in SINK_KINDS:
        if pattern.search(symbol):
            tags.append(tag)
    if SANITIZERS.search(symbol):
        tags.append("sanitizer")
    return tags


# ---------------------------------------------------------------------------
# Business tagging
# ---------------------------------------------------------------------------
AUTHZ_PATTERNS = re.compile(
    r"(?i)(has_?(?:permission|role|authority|access)|is_?(?:admin|manager|authorized|"
    r"authenticated|owner|allowed)|check_?(?:permission|access|authorization|acl|role)|"
    r"require_?(?:role|permission|auth|login|admin|approval)|"
    r"authorize|authoriz|ensure_?(?:permission|authorized)|"
    r"PreAuthorize|Secured|RolesAllowed|can_?(?:approve|access|edit)|"
    r"verify_?(?:approval|permission|signature|token)|"
    r"approved_?by|manager_?approval|maker_?checker|dual_?control|"
    r"grant|denyAccess|access_?control)")

ENDPOINT_PATTERNS = re.compile(
    r"(?i)(app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|"
    r"RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|"
    r"RestController|Controller|route|api_route|add_route|HttpGet|HttpPost|"
    r"web::(get|post|resource|scope)|actix_web|axum::routing)")

ENTRYPOINT_PATTERNS_TAG = re.compile(
    r"(?i)\b(main|run_app|start_server|bootstrap)\b|SpringBootApplication|main\s*\("
)

DB_PATTERNS = re.compile(
    r"(?i)(\.save|\.insert|\.update|\.delete|\.find|\.findBy|\.findOne|\.persist|"
    r"\.merge|\.commit|\.rollback|\.execute|\.query|Repository|EntityManager|"
    r"session\.add|db\.|collection\.|\.upsert|\.create\b|\.transaction)")

#: Domain vocabulary used to tag business relevance of a symbol/function.
BUSINESS_VOCABULARY: dict[str, re.Pattern] = {
    "payment": re.compile(r"(?i)\b(payment|pay|charge|checkout|invoice|billing|"
                          r"settle|settlement|remittance|payout|transaction|txn)\b"),
    "refund": re.compile(r"(?i)\b(refund|reversal|chargeback|void|cancel_?payment)\b"),
    "money": re.compile(r"(?i)\b(amount|balance|currency|price|total|fee|"
                        r"limit|threshold|credit|debit|ledger)\b"),
    "auth": re.compile(r"(?i)\b(login|logout|auth|token|session|password|"
                       r"credential|mfa|otp|sso)\b"),
    "pii": re.compile(r"(?i)\b(ssn|aadhaar|pan\b|passport|dob|birthdate|email|"
                      r"phone|address|card_?number|cvv|iban|account_?number)\b"),
    "healthcare": re.compile(r"(?i)\b(patient|diagnosis|prescription|clinical|ehr|phi)\b"),
    "order": re.compile(r"(?i)\b(order|cart|shipment|fulfil|delivery|inventory|sku)\b"),
    "loan": re.compile(r"(?i)\b(loan|disburse|emi|interest|repayment|collateral|underwrit)\b"),
    "kyc": re.compile(r"(?i)\b(kyc|aml|sanction|onboard|verification|compliance)\b"),
}


def business_tags_for(node: USTNode) -> list[str]:
    subject = " ".join(filter(None, [node.symbol, node.name, node.enclosing_function,
                                     node.enclosing_class]))
    if not subject.strip():
        return []
    tags: list[str] = []
    if AUTHZ_PATTERNS.search(subject):
        tags.append("authorization_check")
    if ENDPOINT_PATTERNS.search(subject):
        tags.append("api_endpoint")
    if ENTRYPOINT_PATTERNS_TAG.search(node.name or subject):
        tags.append("entry_point")
    if DB_PATTERNS.search(node.symbol or "") or DB_PATTERNS.search(node.name or ""):
        tags.append("database_operation")
    for domain, pattern in BUSINESS_VOCABULARY.items():
        if pattern.search(subject):
            tags.append(domain)
    return tags


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
_SEMANTIC_PROMOTION = {
    "crypto": USTNodeType.CRYPTO_OPERATION,
    "authorization_check": USTNodeType.AUTHORIZATION_CHECK,
    "api_endpoint": USTNodeType.API_ENDPOINT,
    "database_operation": USTNodeType.DATABASE_OPERATION,
}


def tag_node(node: USTNode, *, file_imports: Iterable[str] = ()) -> USTNode:
    """Attach crypto/security/business tags to a single node (in place)."""
    if node.type in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION,
                     USTNodeType.ANNOTATION, USTNodeType.ASSIGNMENT,
                     USTNodeType.FUNCTION):
        crypto = crypto_tags_for(node) if node.type != USTNodeType.FUNCTION else []
        if crypto:
            node.crypto_tags = crypto
        security = security_tags_for(node)
        if security:
            node.security_tags = security
        business = business_tags_for(node)
        if business:
            node.business_tags = business

    if node.type is USTNodeType.IMPORT and node.name and CRYPTO_IMPORT_HINTS.search(node.name):
        node.crypto_tags = ["crypto_import"]
        algorithm = resolve_algorithm(node.name)
        if algorithm:
            node.crypto_tags.append(f"algorithm:{algorithm}")
    return node


def promote_semantic_types(node: USTNode) -> USTNode:
    """Re-type a structural node when a semantic tag makes it meaningful.

    Only CALL/OBJECT_CREATION nodes are promoted — promoting a function
    declaration would lose the structural information engines rely on.
    """
    if node.type not in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION):
        return node
    all_tags = node.crypto_tags + node.business_tags
    for tag, new_type in _SEMANTIC_PROMOTION.items():
        if tag in all_tags:
            node.metadata.setdefault("structural_type", node.type.value)
            node.type = new_type
            break
    return node


def tag_file(ust_file: USTFile, *, promote: bool = False) -> USTFile:
    """Tag every node in a file. `promote` re-types semantic call nodes."""
    for node in ust_file.nodes:
        tag_node(node, file_imports=ust_file.imports)
        if promote:
            promote_semantic_types(node)
    return ust_file
