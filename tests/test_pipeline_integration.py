"""
End-to-end pipeline tests over a realistic mixed-language repository,
plus the unified risk engine and the resilience guarantees.
"""
from __future__ import annotations

import json

import pytest

from guardian.config import GuardianConfig
from guardian.core.models import Finding, ScanResult
from guardian.core.pipeline import ScanPipeline
from guardian.core.registry import load_builtin_plugins
from guardian.core.unified_risk import compute_unified_risk, score_finding
from guardian.evidence.store import EvidenceStore

REQUIREMENTS = """# Business Requirements

- Refunds above INR 50,000 require manager approval.
- All payment transactions must be logged for audit purposes.
"""

JAVA_PAYMENT = """
package com.payflow;
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class PaymentService {
    private static final String API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e";

    public byte[] encryptPayment(String amount) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        return cipher.doFinal(amount.getBytes());
    }

    public String fingerprint(String cardNumber) throws Exception {
        return MessageDigest.getInstance("MD5").digest(cardNumber.getBytes()).toString();
    }

    public void lookup(String userInput) {
        statement.executeQuery("SELECT * FROM payments WHERE id = " + userInput);
    }
}
"""

JAVA_REFUND = """
package com.payflow;
public class RefundService {
    public void processRefund(String customerId, long amount) {
        Refund r = new Refund(customerId, amount);
        refundRepository.save(r);
    }
}
"""

PYTHON_HANDLERS = """
def process_payment(amount, user):
    if not current_user.has_permission("pay"):
        raise Forbidden()
    auditLog.record("payment", amount)
    db.save(amount)

def lookup(user_input):
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""

TS_API = """
export class TokenService {
  makeToken(requestBody: any): string {
    const h = crypto.createHash('sha1');
    return h.digest('hex');
  }
}
"""

RUST_LEDGER = """
use ring::signature::RsaKeyPair;
pub fn sign_ledger(user_input: String) -> Result<(), Error> {
    let key = RsaKeyPair::from_pkcs8(&bytes)?;
    let q = format!("SELECT * FROM ledger WHERE id = {}", user_input);
    conn.execute(&q)?;
    Ok(())
}
"""


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    root = tmp_path_factory.mktemp("payflow")
    (root / "README.md").write_text(
        "# PayFlow\nPayment processing and refund platform for banking transactions.\n")
    (root / "requirements.md").write_text(REQUIREMENTS)
    src = root / "src"
    src.mkdir()
    (src / "PaymentService.java").write_text(JAVA_PAYMENT)
    (src / "RefundService.java").write_text(JAVA_REFUND)
    (src / "handlers.py").write_text(PYTHON_HANDLERS)
    (src / "api.ts").write_text(TS_API)
    (src / "ledger.rs").write_text(RUST_LEDGER)
    return root


@pytest.fixture(scope="module")
def report(repo):
    return ScanPipeline(GuardianConfig()).scan(
        repo, business_requirements=[repo / "requirements.md"])


def categories(report) -> set[str]:
    return {f["category"] for f in report["scan"]["findings"]}


# ---------------------------------------------------------------------------
class TestPipelineShape:
    def test_report_contains_every_section(self, report):
        for key in ("tool", "repository", "scan", "risk", "unified_risk", "ust",
                    "evidence", "engines", "quantum", "business_intent",
                    "business_domain", "ai", "discovery", "errors"):
            assert key in report, f"report is missing '{key}'"

    def test_report_is_json_serialisable(self, report):
        json.dumps(report, default=str)

    def test_no_stage_errors_on_a_healthy_repository(self, report):
        assert report["errors"] == []

    def test_legacy_risk_key_is_preserved(self, report):
        """Backward compatibility for existing report consumers."""
        for key in ("security_score", "alignment_score", "overall_risk_score",
                    "merge_decision", "findings"):
            assert key in report["risk"]


class TestMultiLanguageAnalysis:
    def test_all_five_languages_parsed_by_tree_sitter(self, report):
        ust = report["ust"]
        assert set(ust["languages"]) == {"java", "python", "typescript", "rust"}
        assert ust["parse_failures"] == 0
        assert ust["parsers"].get("tree-sitter", 0) == 5

    def test_findings_span_every_language(self, report):
        languages = {f["language"] for f in report["scan"]["findings"] if f["language"]}
        assert {"java", "python", "rust"} <= languages

    @pytest.mark.parametrize("category", [
        "SQL Injection", "Weak Crypto", "Hardcoded Secret",
        "Quantum Migration Inventory", "Business Intent Violation",
    ])
    def test_expected_categories_detected(self, report, category):
        assert category in categories(report)

    def test_sql_injection_found_in_java_python_and_rust(self, report):
        sqli = [f for f in report["scan"]["findings"]
                if f["category"] == "SQL Injection"]
        assert {f["language"] for f in sqli} >= {"java", "python", "rust"}


class TestEvidenceGrounding:
    def test_evidence_store_is_populated(self, report):
        evidence = report["evidence"]
        assert evidence["total"] > 10
        assert "crypto_usage" in evidence["by_type"]
        assert "taint_flow" in evidence["by_type"]

    def test_every_cited_evidence_id_exists(self, report):
        known = {e["id"] for e in report["evidence_items"]}
        for finding in report["scan"]["findings"]:
            for eid in finding.get("evidence_ids", []):
                assert eid in known, f"{finding['category']} cites unknown {eid}"

    def test_ust_backed_findings_carry_evidence_and_function(self, report):
        ust_findings = [f for f in report["scan"]["findings"]
                        if (f.get("engine") or "") in ("security", "quantum",
                                                       "business_intent")]
        assert ust_findings
        assert all(f["evidence_ids"] for f in ust_findings)

    def test_findings_are_deterministic_without_an_api_key(self, report):
        sources = {f["source"] for f in report["scan"]["findings"]}
        assert sources == {"DETERMINISTIC"}


class TestBusinessIntentIntegration:
    def test_violation_detected_for_unimplemented_control(self, report):
        verdicts = report["business_intent"]["verdicts"]
        refund = next(v for v in verdicts if "refund" in v["policy"].lower())
        assert refund["verdict"] == "VIOLATION"
        assert "processRefund" in refund["missing_control_in"]

    def test_alignment_score_feeds_the_risk_engine(self, report):
        measured = report["business_intent"]["alignment_score"]
        assert report["unified_risk"]["alignment_score"] == measured


class TestQuantumIntegration:
    def test_cbom_is_produced(self, report):
        cbom = report["quantum"]
        algorithms = {e["algorithm"] for e in cbom["entries"]}
        assert "RSA" in algorithms
        assert "MD5" in algorithms
        assert cbom["readiness_score"] < 100

    def test_quantum_summary_is_preserved_for_existing_consumers(self, report):
        summary = report["quantum_summary"]
        assert summary["total_crypto_usages"] > 0
        assert "RSA" in summary["quantum_vulnerable_algorithms"]

    def test_quantum_inventory_does_not_drive_the_security_score(self, report):
        inventory = [f for f in report["scan"]["findings"]
                     if f["category"] == "Quantum Migration Inventory"]
        assert inventory
        assert all(f["severity"] == "Info" for f in inventory)
        scored = {d["category"] for d in report["unified_risk"]["findings"]}
        assert "Quantum Migration Inventory" not in scored


class TestReporters:
    @pytest.mark.parametrize("name", ["json", "sarif", "html", "csv", "pdf"])
    def test_every_reporter_renders(self, report, name):
        reporter = load_builtin_plugins().reporter(name)
        assert reporter is not None
        output = reporter.render(report)
        assert output and len(output) > 200

    def test_sarif_is_valid_json_with_provenance(self, report):
        sarif = json.loads(load_builtin_plugins().reporter("sarif").render(report))
        assert sarif["version"] == "2.1.0"
        results = sarif["runs"][0]["results"]
        assert results
        assert all("source" in r["properties"] for r in results)

    def test_csv_finding_id_column_is_populated(self, report):
        """Regression: this column read a non-existent key and was empty."""
        csv_text = load_builtin_plugins().reporter("csv").render(report)
        header, first_row = csv_text.splitlines()[0], csv_text.splitlines()[1]
        assert header.startswith("Finding ID")
        assert first_row.split(",")[0].strip(), "Finding ID must not be empty"

    def test_html_shows_provenance_and_sections(self, report):
        html = load_builtin_plugins().reporter("html").render(report)
        assert "Static" in html
        assert "Business Intent" in html
        # "Analysis Basis" never existed as a heading in html_reporter.py
        # (grep across the repo finds it only in this test) -- the real
        # provenance statement is the report footer, which says findings
        # come directly from guardian.core.pipeline.ScanPipeline and
        # nothing on the page is inferred or generated.
        assert "SOURCE OF TECHNICAL TRUTH" in html
        assert "Evidence" in html
        # Quantum Readiness was a product decision to remove, not a section
        # this test should look for: it was never actually implemented, but
        # its score tile, CBOM section, and "Quantum Migration Inventory"
        # finding rows kept leaking into every exported report. Every
        # reporter now sources its finding list from
        # guardian.reporting._shared.visible_findings(), which drops
        # QUANTUM_CATEGORIES rows before rendering -- so the HTML report
        # must NOT mention it. See guardian/reporting/_shared.py.
        assert "Quantum Readiness" not in html
        assert "Quantum Migration Inventory" not in html


# ---------------------------------------------------------------------------
class TestUnifiedRisk:
    def _result(self, findings) -> ScanResult:
        result = ScanResult(target="t", files_scanned=1, findings=findings)
        result.finish()
        return result

    def test_clean_repository_scores_well(self):
        risk = compute_unified_risk(self._result([]))
        assert risk.security_score == 100.0
        assert risk.pr_risk == 0.0

    def test_ai_findings_are_damped_below_deterministic(self):
        base = dict(category="SQL Injection", severity="High", rule_id="X",
                    file="a.py", line=1, snippet="s", recommendation="r",
                    confidence=0.9)
        deterministic = score_finding(Finding(**base, source="DETERMINISTIC"))
        validated = score_finding(Finding(**base, source="AI_VALIDATED"))
        suggested = score_finding(Finding(**base, source="AI_SUGGESTED"))
        assert deterministic.score > validated.score > suggested.score

    def test_tainted_finding_scores_above_untainted(self):
        base = dict(category="SQL Injection", severity="High", rule_id="X",
                    file="a.py", line=1, snippet="s", recommendation="r")
        assert (score_finding(Finding(**base, tainted=True)).score
                > score_finding(Finding(**base, tainted=False)).score)

    def test_business_critical_evidence_raises_impact(self):
        from guardian.evidence.models import Evidence, EvidenceType
        store = EvidenceStore()
        item = store.add(Evidence(type=EvidenceType.TAINT_FLOW, source="s",
                                  file="a.py", line=1, tags=["payment"]))
        finding = Finding(category="SQL Injection", severity="High", rule_id="X",
                          file="a.py", line=1, snippet="s", recommendation="r",
                          evidence_ids=[item.id])
        with_context = score_finding(finding, evidence_store=store)
        without = score_finding(Finding(category="SQL Injection", severity="High",
                                        rule_id="X", file="a.py", line=1,
                                        snippet="s", recommendation="r"))
        assert with_context.business_impact > without.business_impact

    def test_quantum_is_a_separate_dimension_not_a_security_penalty(self):
        findings = [Finding(category="Quantum Migration Inventory", severity="Info",
                            rule_id="QNT-RSA", file="a.java", line=1, snippet="s",
                            recommendation="r")]
        risk = compute_unified_risk(self._result(findings), quantum_readiness=20.0)
        assert risk.security_score == 100.0, "inventory must not reduce security"
        assert risk.quantum_readiness_score == 20.0
        assert risk.overall_risk_score < 100.0, "but it must affect the composite"

    def test_quantum_gate_is_opt_in(self):
        findings = [Finding(category="Quantum Migration Inventory", severity="Info",
                            rule_id="QNT-RSA", file="a.java", line=1, snippet="s",
                            recommendation="r")]
        ungated = compute_unified_risk(self._result(findings), quantum_gate=False)
        gated = compute_unified_risk(self._result(findings), quantum_gate=True)
        assert "PQC" not in ungated.merge_decision
        assert "PQC" in gated.merge_decision

    def test_every_score_input_is_reported(self):
        finding = Finding(category="SQL Injection", severity="High", rule_id="X",
                          file="a.py", line=1, snippet="s", recommendation="r")
        detail = score_finding(finding).to_dict()
        for key in ("severity_factor", "confidence_factor", "business_impact",
                    "reachability", "exploit_likelihood", "source_multiplier", "notes"):
            assert key in detail

    def test_ai_contribution_is_disclosed(self):
        findings = [
            Finding(category="c", severity="High", rule_id="X", file="a.py", line=1,
                    snippet="s", recommendation="r", source="DETERMINISTIC"),
            Finding(category="c", severity="High", rule_id="Y", file="b.py", line=2,
                    snippet="s", recommendation="r", source="AI_VALIDATED"),
        ]
        risk = compute_unified_risk(self._result(findings))
        assert risk.ai_contribution["ai_findings"] == 1
        assert risk.ai_contribution["deterministic_findings"] == 1


# ---------------------------------------------------------------------------
class TestResilience:
    def test_empty_repository(self, tmp_path):
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        assert report["scan"]["total_findings"] == 0
        assert report["errors"] == []

    def test_malformed_sources_do_not_abort_the_scan(self, tmp_path):
        (tmp_path / "broken.py").write_text("def broken(:\n")
        (tmp_path / "broken.java").write_text("public class { {{{")
        (tmp_path / "good.py").write_text(
            "def f(user_input):\n    cursor.execute('S ' + user_input)\n")
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        assert "SQL Injection" in categories(report)

    def test_binary_and_unsupported_files_are_skipped(self, tmp_path):
        (tmp_path / "blob.bin").write_bytes(bytes(range(256)))
        (tmp_path / "notes.txt").write_text("RSA ECDSA MD5 SQL injection")
        (tmp_path / "q.sql").write_text("SELECT * FROM t;")
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        assert report["scan"]["total_findings"] == 0, "prose must not become findings"

    def test_engine_failure_degrades_to_partial_results(self, tmp_path, monkeypatch):
        (tmp_path / "a.py").write_text(
            "def f(user_input):\n    cursor.execute('S ' + user_input)\n")

        from guardian.engines import quantum as quantum_module

        def explode(self, context):
            raise RuntimeError("simulated quantum engine failure")

        monkeypatch.setattr(quantum_module.QuantumReadinessEngine, "analyze", explode)
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)

        assert any("quantum" in e["stage"] for e in report["errors"])
        assert "SQL Injection" in categories(report), "other engines must still run"
        assert report["unified_risk"]["security_score"] < 100

    def test_ai_enabled_without_credentials_still_completes(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        monkeypatch.setattr("guardian.llm.config.load_dotenv", lambda *a, **kw: 0)
        (tmp_path / "a.py").write_text(
            "def f(user_input):\n    cursor.execute('S ' + user_input)\n")
        cfg = GuardianConfig()
        cfg.enable_ai = True
        report = ScanPipeline(cfg).scan(tmp_path)

        assert "SQL Injection" in categories(report)
        assert report["ai"]["enabled"] is True
        assert report["ai"]["configured"] is False
        assert all(f["source"] == "DETERMINISTIC" for f in report["scan"]["findings"])

    def test_config_toggles_disable_engines(self, tmp_path):
        (tmp_path / "a.java").write_text(
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')
        cfg = GuardianConfig(enable_quantum=False, enable_intent=False)
        report = ScanPipeline(cfg).scan(tmp_path)
        assert report["quantum"] is None
        assert "Quantum Migration Inventory" not in categories(report)

    def test_duplicate_detections_are_merged(self, tmp_path):
        """UST engines and legacy plugins overlap; the report must not."""
        (tmp_path / "m.rs").write_text(
            "fn get(user_input: String) {\n"
            "    let q = format!(\"SELECT * FROM t WHERE id = {}\", user_input);\n"
            "    conn.execute(&q);\n}\n")
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        sqli = [f for f in report["scan"]["findings"] if f["category"] == "SQL Injection"]
        assert len(sqli) == 1, f"expected one merged finding, got {len(sqli)}"
        assert sqli[0]["evidence_ids"], "the merged finding keeps its evidence"


class TestDegradedParsing:
    """The platform must stay useful when Tree-sitter is unavailable."""

    @pytest.fixture
    def no_tree_sitter(self, monkeypatch):
        import builtins
        from guardian.ust import parsers

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "tree_sitter" or name.startswith("tree_sitter_"):
                raise ImportError(f"simulated: no module named {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        parsers._parser_cache.clear()
        parsers._unavailable.clear()
        yield
        parsers._parser_cache.clear()
        parsers._unavailable.clear()

    def test_scan_completes_without_tree_sitter(self, tmp_path, no_tree_sitter):
        (tmp_path / "a.py").write_text(
            "import hashlib\n"
            "def f(user_input):\n"
            "    q = 'SELECT ' + user_input\n"
            "    cursor.execute(q)\n"
            "    return hashlib.md5(b'x')\n")
        (tmp_path / "A.java").write_text(
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')
        (tmp_path / "m.rs").write_text("fn f() { let k = RsaKeyPair::from_pkcs8(b); }")

        report = ScanPipeline(GuardianConfig()).scan(tmp_path)

        parsers_used = report["ust"]["parsers"]
        assert "tree-sitter" not in parsers_used
        assert parsers_used.get("python-ast") == 1, "Python keeps full AST analysis"
        assert parsers_used.get("regex") == 2
        assert report["errors"] == []

    def test_python_detection_is_unchanged_without_tree_sitter(self, tmp_path,
                                                               no_tree_sitter):
        (tmp_path / "a.py").write_text(
            "import hashlib\n"
            "def f(user_input):\n"
            "    q = 'SELECT ' + user_input\n"
            "    cursor.execute(q)\n"
            "    return hashlib.md5(b'x')\n")
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        assert {"SQL Injection", "Weak Crypto"} <= categories(report)

    def test_regex_fallback_still_finds_crypto_in_other_languages(self, tmp_path,
                                                                  no_tree_sitter):
        """Regression: a declaration and a call sharing one line lost the call."""
        (tmp_path / "A.java").write_text(
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')
        (tmp_path / "m.rs").write_text("fn f() { let k = RsaKeyPair::from_pkcs8(b); }")
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)

        algorithms = {e["algorithm"] for e in report["quantum"]["entries"]}
        assert "RSA" in algorithms
        files = {f["file"] for f in report["scan"]["findings"]}
        assert {"A.java", "m.rs"} <= files

    def test_regex_findings_carry_lower_confidence(self, tmp_path, no_tree_sitter):
        """A regex scan is weaker ground than a parse, and must say so."""
        (tmp_path / "A.java").write_text(
            'class A { void f() throws Exception { Cipher.getInstance("RSA"); } }')
        report = ScanPipeline(GuardianConfig()).scan(tmp_path)
        java = [f for f in report["scan"]["findings"] if f["file"] == "A.java"]
        assert java and all(f["confidence"] < 1.0 for f in java)
