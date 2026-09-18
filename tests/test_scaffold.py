"""Smoke + behavior tests for the 2.0 architecture layer."""
import json
import textwrap
from pathlib import Path

import pytest

from guardian.config import GuardianConfig
from guardian.core.pipeline import ScanPipeline
from guardian.core.registry import load_builtin_plugins
from guardian.discovery.file_walker import FileWalker
from guardian.discovery.repo_detector import RepositoryDetector
from guardian.intent.classifier import DomainClassifier


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "PayService.java").write_text(textwrap.dedent('''
        public class PayService {
         String apiKey="SECRET_KEY_9";
         public void run(String input){
           String q="SELECT * FROM loans WHERE id='"+input+"'";
         }
        }
    '''))
    (tmp_path / "app.py").write_text(textwrap.dedent('''
        def handler(user_input):
            query = "SELECT * FROM accounts WHERE id=" + user_input
            cursor.execute(query)
    '''))
    (tmp_path / "index.js").write_text('el.innerHTML = "<b>" + userName;\n')
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\nrequests\n")
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\nENV API_SECRET=abc123xyz\n")
    (tmp_path / "README.md").write_text(
        "# Loan ledger\nA banking platform for loan accounts, payments and transactions.")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("eval(x)")
    return tmp_path


def test_walker_ignores_node_modules(sample_repo):
    files = list(FileWalker(GuardianConfig()).walk(sample_repo))
    assert not any("node_modules" in str(f) for f in files)


def test_repo_detection(sample_repo):
    files = list(FileWalker(GuardianConfig()).walk(sample_repo))
    profile = RepositoryDetector().detect(sample_repo, files)
    assert profile.primary_language in ("Java", "Python", "JavaScript")
    assert "pip" in profile.build_tools
    assert "Flask" in profile.frameworks
    assert "cloud-native" in profile.architecture


def test_registry_routes_extensions():
    reg = load_builtin_plugins()
    assert reg.language_for(".java").name == "java"
    assert reg.language_for(".py").name == "python"
    assert reg.language_for(".tsx").name == "javascript"
    assert reg.language_for(".zig") is None


def test_domain_classifier_banking(sample_repo):
    verdict = DomainClassifier().classify(sample_repo)
    assert verdict.domain == "Banking / FinTech"
    assert verdict.confidence > 0
    assert verdict.evidence


def test_domain_classifier_unclassified(tmp_path):
    (tmp_path / "x.py").write_text("print('hi')")
    verdict = DomainClassifier().classify(tmp_path)
    assert verdict.domain == "Unclassified"


def test_full_pipeline(sample_repo):
    report = ScanPipeline(GuardianConfig()).scan(sample_repo)
    cats = {f["category"] for f in report["scan"]["findings"]}
    # language plugins
    assert "SQL Injection" in cats
    assert "Hardcoded Secret" in cats
    assert "XSS" in cats
    # infrastructure analyzer
    assert "Root Container" in cats
    assert "Exposed Secret" in cats
    # dependency analyzer (requests has no pinned version)
    assert "Unpinned Dependency" in cats
    # risk + repo + domain sections present
    assert 0 <= report["risk"]["overall_risk_score"] <= 100
    assert report["business_domain"]["domain"] == "Banking / FinTech"
    assert report["repository"]["primary_language"]


def test_sarif_reporter(sample_repo):
    reg = load_builtin_plugins()
    report = ScanPipeline(GuardianConfig(), reg).scan(sample_repo)
    sarif = json.loads(reg.reporter("sarif").render(report))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["results"], "SARIF must contain results"
    assert all(r["ruleIndex"] < len(run["tool"]["driver"]["rules"]) for r in run["results"])


def test_html_reporter(sample_repo):
    reg = load_builtin_plugins()
    report = ScanPipeline(GuardianConfig(), reg).scan(sample_repo)
    html_out = reg.reporter("html").render(report)
    assert "<html" in html_out and "SQL Injection" in html_out


def test_config_toggles_disable_analyzers(sample_repo):
    cfg = GuardianConfig(enable_infrastructure=False, enable_dependencies=False,
                         enable_quantum=False, enable_intent=False)
    report = ScanPipeline(cfg).scan(sample_repo)
    cats = {f["category"] for f in report["scan"]["findings"]}
    assert "Root Container" not in cats
    assert "Unpinned Dependency" not in cats
    assert report["business_domain"] is None


# ---- quantum precision regressions (Hyperswitch v6 audit) -------------
class TestQuantumPrecision:
    def _scan(self, text, label):
        from guardian.quantum.detector import QuantumDetector
        return QuantumDetector().scan_text(text, label)

    def test_spec_is_not_ecdsa(self):
        assert self._scan("const specName = Cypress.spec.name;", "a.js") == []
        assert self._scan('_SPEC_EXTENSIONS = (".spec.js", ".cy.ts")', "a.py") == []

    def test_comments_are_skipped(self):
        assert self._scan("// NOTE: test RSA public key for encryption", "a.js") == []
        assert self._scan("# uses hashlib.md5 internally", "a.py") == []

    def test_real_crypto_still_detected(self):
        assert self._scan('KeyPairGenerator.getInstance("RSA")', "A.java")
        assert self._scan("key = ec.generate_private_key(ec.SECP256R1())", "a.py")
        assert self._scan("let kp = RsaKeyPair::from_pkcs8(der)?;", "a.rs")
        assert self._scan("crypto.createHash('md5').update(x)", "a.js")

    def test_prose_numbers_are_not_aes128(self):
        assert self._scan("retry_after = 128  # AES has nothing to do with this", "a.py") == []
        assert self._scan("int poolSize = 128; // AES pool comment", "A.java") == []

    def test_unknown_extensions_not_scanned(self):
        assert self._scan("RSA RSA RSA ec. dh.", "notes.txt") == []


def test_quantum_findings_are_inventory_not_alarms(tmp_path):
    """Shor-class usages surface as Info inventory, aggregated per file,
    and never hard-block the merge unless the gate is opted into."""
    (tmp_path / "crypto.rs").write_text(
        "let kp = RsaKeyPair::from_pkcs8(a)?;\nlet kp2 = RsaKeyPair::from_pkcs8(b)?;\n")
    report = ScanPipeline(GuardianConfig()).scan(tmp_path)
    qf = [f for f in report["scan"]["findings"]
          if f["category"] == "Quantum Migration Inventory"]
    assert len(qf) == 1, "must aggregate to one finding per (file, algorithm)"
    assert qf[0]["severity"] == "Info"
    assert "2 usages" in qf[0]["recommendation"]
    assert "PQC" not in report["risk"]["merge_decision"], "gate must be opt-in"

    gated = ScanPipeline(GuardianConfig(enable_quantum_gate=True)).scan(tmp_path)
    assert "PQC" in gated["risk"]["merge_decision"]
