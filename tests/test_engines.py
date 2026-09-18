"""
Engine tests — UST security analysis and quantum readiness (Layers A/B).

These verify the refactored flow: rule match -> candidate evidence ->
contextual check -> finding, with every finding citing real evidence IDs.
"""
from __future__ import annotations

import pytest

from guardian.config import GuardianConfig
from guardian.core.context import AnalysisContext, RepositoryContext
from guardian.engines.base import EngineResult, run_engine
from guardian.engines.quantum import QuantumReadinessEngine
from guardian.engines.security import SecurityEngine
from guardian.evidence.models import EvidenceType
from guardian.quantum.classification import (
    QuantumStatus, build_cbom, classify, is_post_quantum, is_quantum_vulnerable,
)
from guardian.ust import USTBuilder


def make_context(tmp_path, files: dict[str, str]) -> AnalysisContext:
    """Write `files` into tmp_path and build a fully populated context."""
    paths = []
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        paths.append(p)
    repo = RepositoryContext(root=tmp_path, source_files=paths)
    ctx = AnalysisContext(repository=repo, config=GuardianConfig())
    ctx.ust = USTBuilder().build_repository(tmp_path, paths)
    return ctx


def categories(result: EngineResult) -> set[str]:
    return {f.category for f in result.findings}


# ---------------------------------------------------------------------------
# Security engine
# ---------------------------------------------------------------------------
class TestSecurityEngineTaint:
    def test_python_sql_injection_from_taint(self, tmp_path):
        ctx = make_context(tmp_path, {"app.py": (
            "def handler(user_input):\n"
            "    q = 'SELECT * FROM t WHERE id = ' + user_input\n"
            "    cursor.execute(q)\n")})
        result = run_engine(SecurityEngine(), ctx)
        assert "SQL Injection" in categories(result)
        finding = next(f for f in result.findings if f.category == "SQL Injection")
        assert finding.tainted
        assert finding.function == "handler"
        assert finding.language == "python"

    def test_java_sql_injection(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            "public class A {\n"
            "  void run(String userInput) {\n"
            "    statement.executeQuery(\"SELECT * FROM t WHERE x = \" + userInput);\n"
            "  }\n}\n")})
        assert "SQL Injection" in categories(run_engine(SecurityEngine(), ctx))

    def test_rust_sql_injection_via_format_macro(self, tmp_path):
        ctx = make_context(tmp_path, {"m.rs": (
            "fn get(user_input: String) {\n"
            "    let q = format!(\"SELECT * FROM t WHERE id = {}\", user_input);\n"
            "    conn.execute(&q);\n}\n")})
        assert "SQL Injection" in categories(run_engine(SecurityEngine(), ctx))

    def test_parameterised_query_is_not_reported(self, tmp_path):
        """The regression that matters most: no false positive on the fix."""
        ctx = make_context(tmp_path, {"safe.py": (
            "def handler(user_input):\n"
            "    cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))\n")})
        assert "SQL Injection" not in categories(run_engine(SecurityEngine(), ctx))

    def test_command_injection(self, tmp_path):
        ctx = make_context(tmp_path, {"c.py": (
            "def run(user_input):\n"
            "    cmd = 'ls ' + user_input\n"
            "    os.system(cmd)\n")})
        assert "Command Injection" in categories(run_engine(SecurityEngine(), ctx))

    def test_evidence_precedes_the_finding(self, tmp_path):
        ctx = make_context(tmp_path, {"app.py": (
            "def handler(user_input):\n"
            "    q = 'SELECT ' + user_input\n"
            "    cursor.execute(q)\n")})
        result = run_engine(SecurityEngine(), ctx)
        finding = next(f for f in result.findings if f.category == "SQL Injection")
        assert finding.evidence_ids, "a finding must cite its evidence"
        for eid in finding.evidence_ids:
            assert ctx.evidence.exists(eid), f"finding cites unknown evidence {eid}"
        cited = ctx.evidence.get(finding.evidence_ids[0])
        assert cited.type is EvidenceType.TAINT_FLOW
        assert cited.file == "app.py"


class TestSecurityEngineCrypto:
    @pytest.mark.parametrize("name,source,algorithm", [
        ("h.py", "import hashlib\ndef f(x):\n    return hashlib.md5(x)\n", "MD5"),
        ("A.java", 'class A { void f() { MessageDigest.getInstance("SHA-1"); } }', "SHA-1"),
        ("s.js", "function f(){ crypto.createHash('md5'); }", "MD5"),
        ("m.rs", "fn f() { let h = Md5::new(); }", "MD5"),
    ])
    def test_broken_hashes_across_languages(self, tmp_path, name, source, algorithm):
        ctx = make_context(tmp_path, {name: source})
        result = run_engine(SecurityEngine(), ctx)
        assert "Weak Crypto" in categories(result)
        finding = next(f for f in result.findings if f.category == "Weak Crypto")
        assert algorithm in finding.reason

    def test_des_cipher(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f() throws Exception { Cipher.getInstance("DES"); } }')})
        assert "Weak Crypto" in categories(run_engine(SecurityEngine(), ctx))

    def test_ecb_mode_flagged(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f() throws Exception '
            '{ Cipher.getInstance("AES/ECB/PKCS5Padding"); } }')})
        assert "Weak Crypto" in categories(run_engine(SecurityEngine(), ctx))

    def test_strong_crypto_is_not_a_finding(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f() throws Exception '
            '{ Cipher.getInstance("AES/GCM/NoPadding"); '
            'MessageDigest.getInstance("SHA-384"); } }')})
        assert "Weak Crypto" not in categories(run_engine(SecurityEngine(), ctx))

    def test_one_finding_per_chained_crypto_call(self, tmp_path):
        """hashlib.md5(x).hexdigest() is one operation, not two."""
        ctx = make_context(tmp_path, {"h.py": (
            "import hashlib\ndef f(x):\n    return hashlib.md5(x).hexdigest()\n")})
        result = run_engine(SecurityEngine(), ctx)
        assert len([f for f in result.findings if f.category == "Weak Crypto"]) == 1


class TestSecurityEngineOther:
    def test_disabled_tls_verification_rust(self, tmp_path):
        ctx = make_context(tmp_path, {"c.rs": (
            "fn f() { let c = Client::builder()"
            ".danger_accept_invalid_certs(true).build(); }")})
        result = run_engine(SecurityEngine(), ctx)
        assert "Broken Authentication" in categories(result)
        assert any(f.severity == "Critical" for f in result.findings
                   if f.category == "Broken Authentication")

    def test_sensitive_logging(self, tmp_path):
        ctx = make_context(tmp_path, {"a.py": (
            "def f(password):\n    logger.info('login password=' + password)\n")})
        assert "Sensitive Logging" in categories(run_engine(SecurityEngine(), ctx))

    def test_insecure_random_only_in_security_context(self, tmp_path):
        secure_ctx = make_context(tmp_path, {"t.py": (
            "def make_token():\n    return random.random()\n")})
        assert "Weak Crypto" in categories(run_engine(SecurityEngine(), secure_ctx))

    def test_insecure_random_ignored_outside_security_context(self, tmp_path):
        ctx = make_context(tmp_path, {"g.py": (
            "def pick_colour():\n    return random.choice(palette)\n")})
        assert "Weak Crypto" not in categories(run_engine(SecurityEngine(), ctx))

    def test_hardcoded_secret_detected(self, tmp_path):
        ctx = make_context(tmp_path, {"c.py": (
            'API_KEY = "sk-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"\n')})
        result = run_engine(SecurityEngine(), ctx)
        assert "Hardcoded Secret" in categories(result)

    def test_env_lookup_is_not_a_hardcoded_secret(self, tmp_path):
        ctx = make_context(tmp_path, {"c.py": (
            'API_KEY = os.environ.get("API_KEY", "changeme")\n')})
        assert "Hardcoded Secret" not in categories(run_engine(SecurityEngine(), ctx))

    def test_placeholder_is_not_a_secret(self, tmp_path):
        ctx = make_context(tmp_path, {"c.py": 'api_key = "your-api-key-here"\n'})
        assert "Hardcoded Secret" not in categories(run_engine(SecurityEngine(), ctx))

    def test_constant_name_equals_value_is_not_a_secret(self, tmp_path):
        ctx = make_context(tmp_path, {"c.java": (
            'class C { String SMTP_PASSWORD = "SMTP_PASSWORD"; }')})
        assert "Hardcoded Secret" not in categories(run_engine(SecurityEngine(), ctx))


class TestStructuralEvidence:
    def test_endpoints_authz_and_db_are_published(self, tmp_path):
        ctx = make_context(tmp_path, {"api.py": (
            '@app.route("/refund")\n'
            'def process_refund(amount):\n'
            '    if not current_user.has_permission("refund"):\n'
            '        raise Forbidden()\n'
            '    return db.execute("UPDATE refunds SET x=1")\n')})
        run_engine(SecurityEngine(), ctx)
        assert ctx.evidence.by_type(EvidenceType.API_ENDPOINT)
        assert ctx.evidence.by_type(EvidenceType.AUTHORIZATION_CHECK)
        assert ctx.evidence.by_type(EvidenceType.DATABASE_OPERATION)


class TestEngineResilience:
    def test_engine_failure_does_not_propagate(self, tmp_path):
        class Exploding:
            name = "boom"

            def analyze(self, context):
                raise RuntimeError("engine exploded")

        ctx = make_context(tmp_path, {"a.py": "x = 1\n"})
        result = run_engine(Exploding(), ctx)
        assert not result.ok
        assert "engine exploded" in result.error
        assert ctx.errors and ctx.errors[0]["stage"] == "boom"

    def test_unparsable_file_does_not_stop_other_files(self, tmp_path):
        ctx = make_context(tmp_path, {
            "broken.py": "def broken(:\n",
            "good.py": "def f(user_input):\n    cursor.execute('S ' + user_input)\n",
        })
        result = run_engine(SecurityEngine(), ctx)
        assert "SQL Injection" in categories(result)

    def test_empty_repository(self, tmp_path):
        ctx = make_context(tmp_path, {})
        result = run_engine(SecurityEngine(), ctx)
        assert result.ok and result.findings == []


# ---------------------------------------------------------------------------
# Quantum: Layer B classification
# ---------------------------------------------------------------------------
class TestQuantumClassification:
    @pytest.mark.parametrize("algorithm", ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"])
    def test_shor_vulnerable_algorithms(self, algorithm):
        c = classify(algorithm)
        assert c.status is QuantumStatus.VULNERABLE
        assert is_quantum_vulnerable(algorithm)
        assert c.migration_target

    @pytest.mark.parametrize("algorithm", ["ML-KEM", "ML-DSA", "SLH-DSA"])
    def test_pqc_algorithms(self, algorithm):
        c = classify(algorithm)
        assert c.status is QuantumStatus.PQC
        assert is_post_quantum(algorithm)
        assert "FIPS" in c.nist_standard

    @pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "DES", "3DES", "RC4"])
    def test_classically_broken(self, algorithm):
        assert classify(algorithm).status is QuantumStatus.BROKEN

    def test_grover_weakened(self):
        assert classify("AES-128").status is QuantumStatus.WEAKENED
        assert classify("AES-128").post_quantum_strength_bits == 64

    def test_quantum_safe(self):
        assert classify("AES-256").status is QuantumStatus.SAFE
        assert classify("SHA-384").status is QuantumStatus.SAFE

    def test_unknown_algorithm_is_flagged_never_assumed_safe(self):
        c = classify("")
        assert c.status is QuantumStatus.UNKNOWN
        assert not is_quantum_vulnerable("")
        novel = classify("SomeBrandNewCipher")
        assert novel.status is QuantumStatus.UNKNOWN
        assert "No trusted classification" in novel.rationale

    def test_nist_standards_are_cited(self):
        assert classify("RSA").nist_standard == "FIPS 203 / FIPS 204"
        assert classify("ML-KEM").nist_standard == "FIPS 203"
        assert classify("ML-DSA").nist_standard == "FIPS 204"
        assert classify("SLH-DSA").nist_standard == "FIPS 205"


# ---------------------------------------------------------------------------
# Quantum: Layer A discovery + CBOM
# ---------------------------------------------------------------------------
class TestQuantumDiscovery:
    def test_discovers_crypto_across_languages(self, tmp_path):
        ctx = make_context(tmp_path, {
            "P.java": 'class P { void f() throws Exception { Cipher.getInstance("RSA"); } }',
            "h.py": "import hashlib\nh = hashlib.sha256(b'x')\n",
            "s.js": "const s = crypto.createSign('RSA-SHA256');",
            "m.rs": "fn f() { let k = RsaKeyPair::from_pkcs8(b); }",
        })
        result = run_engine(QuantumReadinessEngine(), ctx)
        cbom = result.output
        algorithms = {e.algorithm for e in cbom.entries}
        assert "RSA" in algorithms
        assert "SHA-256" in algorithms
        assert {e.classification.status for e in cbom.entries} & {QuantumStatus.VULNERABLE}

    def test_comment_mentioning_rsa_produces_no_evidence(self, tmp_path):
        ctx = make_context(tmp_path, {
            "notes.py": "# TODO: migrate our RSA and ECDSA usage to ML-KEM\nx = 1\n"})
        result = run_engine(QuantumReadinessEngine(), ctx)
        assert result.output.entries == []
        assert result.findings == []

    def test_runtime_algorithm_is_recorded_as_unresolved_not_guessed(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f(String algo) throws Exception '
            '{ Cipher.getInstance(algo); } }')})
        result = run_engine(QuantumReadinessEngine(), ctx)
        cbom = result.output
        assert cbom.unresolved_call_sites == 1
        unknown = next(e for e in cbom.entries if e.algorithm == "unknown")
        assert unknown.classification.status is QuantumStatus.UNKNOWN
        assert not result.findings, "an unresolved algorithm is not a migration finding"

    def test_pqc_usage_is_recognised(self, tmp_path):
        ctx = make_context(tmp_path, {"pqc.py": (
            'from oqs import KeyEncapsulation\n'
            'kem = KeyEncapsulation("ML-KEM-768")\n')})
        result = run_engine(QuantumReadinessEngine(), ctx)
        assert any(e.classification.status is QuantumStatus.PQC
                   for e in result.output.entries)

    def test_imports_are_dependencies_not_algorithm_usages(self, tmp_path):
        ctx = make_context(tmp_path, {"i.py": "import hashlib\nimport rsa\n"})
        cbom = run_engine(QuantumReadinessEngine(), ctx).output
        assert cbom.total_occurrences == 0, "an import is not an algorithm usage"
        assert cbom.dependencies, "but it must still be inventoried"

    def test_evidence_ids_are_linked_into_the_cbom(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')})
        result = run_engine(QuantumReadinessEngine(), ctx)
        entry = next(e for e in result.output.entries if e.algorithm == "RSA")
        assert entry.evidence_ids
        assert ctx.evidence.exists(entry.evidence_ids[0])

    def test_findings_are_info_inventory_and_aggregated(self, tmp_path):
        """Policy: using RSA today is a migration item, not a live vuln."""
        ctx = make_context(tmp_path, {"A.java": (
            'class A {\n'
            '  void f() throws Exception { Cipher.getInstance("RSA"); }\n'
            '  void g() throws Exception { Cipher.getInstance("RSA"); }\n}\n')})
        result = run_engine(QuantumReadinessEngine(), ctx)
        rsa = [f for f in result.findings if "RSA" in (f.rule_id or "")]
        assert len(rsa) == 1, "one finding per (file, algorithm)"
        assert rsa[0].severity == "Info"
        assert len(rsa[0].evidence_ids) == 2

    def test_findings_cite_real_evidence(self, tmp_path):
        ctx = make_context(tmp_path, {"h.py": "import hashlib\nh = hashlib.md5(b'x')\n"})
        result = run_engine(QuantumReadinessEngine(), ctx)
        for finding in result.findings:
            assert finding.evidence_ids
            for eid in finding.evidence_ids:
                assert ctx.evidence.exists(eid)


class TestCBOM:
    def test_readiness_score_bounds(self, tmp_path):
        clean = make_context(tmp_path / "a", {"x.py": "x = 1\n"})
        assert run_engine(QuantumReadinessEngine(), clean).output.readiness_score() == 100.0

    def test_vulnerable_crypto_lowers_the_score(self, tmp_path):
        ctx = make_context(tmp_path, {"A.java": (
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')})
        assert run_engine(QuantumReadinessEngine(), ctx).output.readiness_score() < 100

    def test_pqc_usage_scores_better_than_rsa(self, tmp_path):
        rsa = make_context(tmp_path / "rsa", {"A.java": (
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')})
        pqc = make_context(tmp_path / "pqc", {"p.py": (
            'from oqs import KeyEncapsulation\nk = KeyEncapsulation("ML-KEM-768")\n')})
        rsa_score = run_engine(QuantumReadinessEngine(), rsa).output.readiness_score()
        pqc_score = run_engine(QuantumReadinessEngine(), pqc).output.readiness_score()
        assert pqc_score > rsa_score

    def test_empty_cbom_serialises(self):
        cbom = build_cbom([], target="empty")
        d = cbom.to_dict()
        assert d["readiness_score"] == 100.0
        assert d["entries"] == []
        assert d["total_occurrences"] == 0

    def test_cbom_orders_vulnerable_first(self, tmp_path):
        ctx = make_context(tmp_path, {
            "A.java": ('class A { void f() throws Exception {\n'
                       '  MessageDigest.getInstance("SHA-384");\n'
                       '  Cipher.getInstance("RSA");\n} }\n')})
        entries = run_engine(QuantumReadinessEngine(), ctx).output.to_dict()["entries"]
        assert entries[0]["algorithm"] == "RSA"


class TestLegacyQuantumPreserved:
    """The regex detector/mapper/scorer remain available as a fallback."""

    def test_regex_detector_still_works(self):
        from guardian.quantum.detector import QuantumDetector
        usages = QuantumDetector().scan_text(
            'KeyPairGenerator.getInstance("RSA")', "A.java")
        assert any(u.algorithm == "RSA" for u in usages)

    def test_migration_mapper_still_works(self):
        from guardian.quantum.mapper import MigrationMapper
        rec = MigrationMapper().get_recommendation("RSA")
        assert rec is not None and "ML-KEM" in rec.replacement_algorithm
