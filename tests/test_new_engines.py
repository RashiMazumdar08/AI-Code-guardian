"""
Unit tests for:
  - Business Intent Engine
  - Quantum Readiness Engine
  - Threat Intelligence Engine
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json, tempfile, os


# ============================================================
# Business Intent Engine
# ============================================================

class TestRequirementLoader:
    def test_load_json(self, tmp_path):
        from guardian.intent.legacy.loader import RequirementLoader
        data = [{"id": "JIRA-1", "summary": "Loan approval", "description": "Only managers can approve loans above ₹10 lakh.", "acceptance_criteria": ["Manager role required"]}]
        f = tmp_path / "stories.json"
        f.write_text(json.dumps(data))
        loader = RequirementLoader()
        reqs = loader.load(f)
        assert len(reqs) == 1
        assert reqs[0].source_id == "JIRA-1"
        assert "manager" in reqs[0].content.lower()

    def test_load_markdown(self, tmp_path):
        from guardian.intent.legacy.loader import RequirementLoader
        md = "# Auth\n\n## Login\nOnly verified users must authenticate.\n\n## Logout\nSession must be invalidated."
        f = tmp_path / "brd.md"
        f.write_text(md)
        loader = RequirementLoader()
        reqs = loader.load(f)
        assert len(reqs) >= 1
        assert any("verif" in r.content.lower() for r in reqs)

    def test_load_text(self, tmp_path):
        from guardian.intent.legacy.loader import RequirementLoader
        f = tmp_path / "srs.txt"
        f.write_text("The system must validate all user inputs. Passwords must be at least 12 characters.")
        reqs = RequirementLoader().load(f)
        assert len(reqs) == 1

    def test_load_dict_inline(self):
        from guardian.intent.legacy.loader import RequirementLoader
        req = RequirementLoader().load({"id": "inline-1", "title": "Test", "description": "Only admins shall access reports."})
        assert req[0].source_id == "inline-1"

    def test_unsupported_extension_fallback(self, tmp_path):
        from guardian.intent.legacy.loader import RequirementLoader
        f = tmp_path / "req.unknownext"
        f.write_text("The system must validate all payments before processing.")
        reqs = RequirementLoader().load(f)
        assert len(reqs) == 1
        assert "payment" in reqs[0].content.lower()


class TestRuleBasedExtractor:
    def test_extracts_authorization_rule(self):
        from guardian.intent.legacy.loader import RequirementLoader
        from guardian.intent.legacy.extractor import RuleBasedExtractor
        from guardian.intent.legacy.models import RuleType
        req = RequirementLoader().load({"id": "T1", "title": "T", "description": "Only managers can approve loans above ₹10 lakh."})[0]
        rules = RuleBasedExtractor().extract(req)
        assert len(rules) >= 1
        assert any(r.rule_type == RuleType.AUTHORIZATION for r in rules)

    def test_extracts_actor_from_sentence(self):
        from guardian.intent.legacy.loader import RequirementLoader
        from guardian.intent.legacy.extractor import RuleBasedExtractor
        req = RequirementLoader().load({"id": "T2", "title": "T", "description": "Only verified merchants may receive settlements."})[0]
        rules = RuleBasedExtractor().extract(req)
        assert any("merchant" in r.actor.lower() for r in rules)

    def test_extracts_condition_numeric(self):
        from guardian.intent.legacy.loader import RequirementLoader
        from guardian.intent.legacy.extractor import RuleBasedExtractor
        req = RequirementLoader().load({"id": "T3", "title": "T", "description": "Managers must approve loans above ₹10,00,000."})[0]
        rules = RuleBasedExtractor().extract(req)
        assert any("10,00,000" in r.condition or "above" in r.condition.lower() for r in rules)

    def test_stable_rule_id(self):
        from guardian.intent.legacy.loader import RequirementLoader
        from guardian.intent.legacy.extractor import RuleBasedExtractor
        req = RequirementLoader().load({"id": "T4", "title": "T", "description": "Only admins shall access the settings panel."})[0]
        r1 = RuleBasedExtractor().extract(req)
        r2 = RuleBasedExtractor().extract(req)
        assert r1[0].rule_id == r2[0].rule_id


class TestBusinessIntentMatcher:
    def test_matched_when_role_check_present(self):
        from guardian.intent.legacy.matcher import KeywordMatcher
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleType
        rule = BusinessRule(requirement_id="T1", actor="manager", action="approve loan", condition="above 10 lakh", expected_outcome="Allowed", rule_type=RuleType.AUTHORIZATION)
        source = "if (user.hasRole('MANAGER')) { approveLoan(amount); }"
        m = KeywordMatcher().match(rule, "LoanService.java", source)
        assert m.status == MatchStatus.MATCHED

    def test_not_implemented_when_no_auth_check(self):
        from guardian.intent.legacy.matcher import KeywordMatcher
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleType
        rule = BusinessRule(requirement_id="T2", actor="admin", action="delete user", condition="", expected_outcome="Allowed", rule_type=RuleType.AUTHORIZATION)
        source = "public void deleteUser(long id) { userRepo.deleteById(id); }"
        m = KeywordMatcher().match(rule, "UserService.java", source)
        assert m.status in (MatchStatus.NOT_IMPLEMENTED, MatchStatus.PARTIAL)

    def test_violated_when_bypass_detected(self):
        from guardian.intent.legacy.matcher import KeywordMatcher
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleType
        rule = BusinessRule(requirement_id="T3", actor="user", action="authenticate", condition="", expected_outcome="Allowed", rule_type=RuleType.AUTHORIZATION)
        source = "public boolean checkAuth(String t) { return true; }"
        m = KeywordMatcher().match(rule, "AuthService.java", source)
        assert m.status == MatchStatus.VIOLATED


class TestBusinessIntentScorer:
    def test_score_all_matched_returns_100(self):
        from guardian.intent.legacy.scorer import BusinessIntentScorer
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleMatch, RuleType
        rule = BusinessRule(requirement_id="R1", actor="admin", action="access", condition="", expected_outcome="Allowed")
        match = RuleMatch(rule=rule, matched_artefact="f.java", status=MatchStatus.MATCHED, confidence=1.0, evidence="ok")
        report = BusinessIntentScorer().score([match])
        assert report.alignment_score == 100.0

    def test_score_unimplemented_lowers_score(self):
        from guardian.intent.legacy.scorer import BusinessIntentScorer
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleMatch
        rule = BusinessRule(requirement_id="R2", actor="manager", action="approve loan", condition="amount > 10L", expected_outcome="Allowed")
        match = RuleMatch(rule=rule, matched_artefact="f.java", status=MatchStatus.NOT_IMPLEMENTED, confidence=0.9, evidence="not found")
        report = BusinessIntentScorer().score([match])
        assert report.alignment_score < 80

    def test_to_findings_emits_business_intent_category(self):
        from guardian.intent.legacy.scorer import BusinessIntentScorer
        from guardian.intent.legacy.models import BusinessRule, MatchStatus, RuleMatch
        rule = BusinessRule(requirement_id="R3", actor="system", action="log audit", condition="", expected_outcome="Audit log written")
        match = RuleMatch(rule=rule, matched_artefact="Service.java", status=MatchStatus.NOT_IMPLEMENTED, confidence=0.85, evidence="no log call")
        report = BusinessIntentScorer().score([match])
        findings = BusinessIntentScorer().to_findings(report)
        assert any(f.category == "Business Intent" for f in findings)


# ============================================================
# Quantum Readiness Engine
# ============================================================

class TestQuantumDetector:
    def test_detects_rsa_java(self):
        from guardian.quantum.detector import QuantumDetector
        src = 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); kpg.initialize(2048);'
        usages = QuantumDetector().scan_text(src, "Crypto.java")
        assert any("RSA" in u.algorithm for u in usages)

    def test_detects_md5_python(self):
        from guardian.quantum.detector import QuantumDetector
        src = "import hashlib\nhash = hashlib.md5(data).hexdigest()"
        usages = QuantumDetector().scan_text(src, "utils.py")
        assert any("MD5" in u.algorithm for u in usages)

    def test_detects_weak_tls_java(self):
        from guardian.quantum.detector import QuantumDetector
        src = 'SSLContext ctx = SSLContext.getInstance("TLSv1");'
        usages = QuantumDetector().scan_text(src, "HttpClient.java")
        assert any("TLS" in u.algorithm or "SSL" in u.algorithm for u in usages)

    def test_detects_ecdsa_java(self):
        from guardian.quantum.detector import QuantumDetector
        src = 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");'
        usages = QuantumDetector().scan_text(src, "Sign.java")
        assert any(u.family.value in ("ECC", "DSA") for u in usages)

    def test_deduplicates_same_line(self):
        from guardian.quantum.detector import QuantumDetector
        src = 'KeyPairGenerator.getInstance("RSA"); Signature.getInstance("SHA256withRSA");'
        usages = QuantumDetector().scan_text(src, "X.java")
        assert len([u for u in usages if u.algorithm == "RSA"]) == 1


class TestMigrationMapper:
    def test_rsa_maps_to_mlkem(self):
        from guardian.quantum.mapper import MigrationMapper
        rec = MigrationMapper().get_recommendation("RSA")
        assert rec is not None
        assert "ML-KEM" in rec.replacement_algorithm or "Kyber" in rec.replacement_algorithm

    def test_md5_has_migration(self):
        from guardian.quantum.mapper import MigrationMapper
        rec = MigrationMapper().get_recommendation("MD5")
        assert rec is not None
        assert "SHA" in rec.replacement_algorithm

    def test_unknown_algo_returns_none(self):
        from guardian.quantum.mapper import MigrationMapper
        assert MigrationMapper().get_recommendation("SomeNewAlgorithm") is None


class TestQuantumReadinessScorer:
    def test_perfect_score_when_no_usages(self):
        from guardian.quantum.scorer import QuantumReadinessScorer
        from guardian.quantum.models import CryptographicBOM
        cbom = CryptographicBOM(target="clean")
        report = QuantumReadinessScorer().score(cbom, [], files_scanned=5)
        assert report.readiness_score == 100.0

    def test_critical_usage_penalizes_score(self):
        from guardian.quantum.scorer import QuantumReadinessScorer
        from guardian.quantum.detector import QuantumDetector
        from guardian.quantum.inventory import CryptoInventoryBuilder
        src = 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");'
        usages = QuantumDetector().scan_text(src, "Crypto.java")
        cbom = CryptoInventoryBuilder().build(usages, "test")
        report = QuantumReadinessScorer().score(cbom, [], files_scanned=1)
        assert report.readiness_score < 100

    def test_to_findings_emits_weak_crypto_category(self):
        from guardian.quantum.scorer import QuantumReadinessScorer
        from guardian.quantum.detector import QuantumDetector
        from guardian.quantum.inventory import CryptoInventoryBuilder
        src = 'MessageDigest md = MessageDigest.getInstance("MD5");'
        usages = QuantumDetector().scan_text(src, "Hash.java")
        cbom = CryptoInventoryBuilder().build(usages, "test")
        findings = QuantumReadinessScorer().to_findings(cbom)
        assert any(f.category == "Weak Crypto" for f in findings)
        assert all(f.cwe == "CWE-327" for f in findings)


# ============================================================
# Threat Intelligence Engine
# ============================================================

class TestCVENormalizer:
    def test_cwe_to_owasp_mapping(self):
        from guardian.threat_intel.normalizer import CVENormalizer
        from guardian.threat_intel.models import CVERecord, FeedSource
        cve = CVERecord(cve_id="CVE-2023-1234", description="SQL injection", cvss_score=9.1,
                        cvss_vector="", epss_score=-1, severity="critical",
                        published="2023-01-01", modified="2023-01-01",
                        cwe_ids=["CWE-89"], source=FeedSource.NVD)
        result = CVENormalizer().normalize(cve)
        assert result.severity == "Critical"
        assert any("Injection" in o for o in result.owasp_categories)

    def test_severity_derived_from_cvss_when_blank(self):
        from guardian.threat_intel.normalizer import CVENormalizer
        from guardian.threat_intel.models import CVERecord, FeedSource
        cve = CVERecord(cve_id="CVE-2023-5678", description="Buffer overflow", cvss_score=7.5,
                        cvss_vector="", epss_score=-1, severity="info",
                        published="2023-01-01", modified="2023-01-01",
                        source=FeedSource.NVD)
        result = CVENormalizer().normalize(cve)
        assert result.severity == "High"


class TestThreatIntelCache:
    def test_cache_miss_on_empty(self, tmp_path):
        from guardian.threat_intel.cache import ThreatIntelCache
        cache = ThreatIntelCache(cache_dir=tmp_path)
        assert cache.get("log4j", "2.14.1") is None

    def test_cache_put_and_get(self, tmp_path):
        from guardian.threat_intel.cache import ThreatIntelCache
        from guardian.threat_intel.models import CVERecord, FeedSource
        cache = ThreatIntelCache(cache_dir=tmp_path)
        cve = CVERecord(cve_id="CVE-2021-44228", description="Log4Shell", cvss_score=10.0,
                        cvss_vector="", epss_score=0.97, severity="Critical",
                        published="2021-12-10", modified="2021-12-15",
                        known_exploited=True, source=FeedSource.NVD)
        cache.put("log4j-core", "2.14.1", [cve])
        result = cache.get("log4j-core", "2.14.1")
        assert result is not None
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-44228"

    def test_cache_clears_correctly(self, tmp_path):
        from guardian.threat_intel.cache import ThreatIntelCache
        from guardian.threat_intel.models import CVERecord, FeedSource
        cache = ThreatIntelCache(cache_dir=tmp_path)
        cve = CVERecord(cve_id="CVE-X", description="test", cvss_score=5.0, cvss_vector="",
                        epss_score=-1, severity="Medium", published="2024-01-01",
                        modified="2024-01-01", source=FeedSource.OSV)
        cache.put("testpkg", None, [cve])
        count = cache.clear_all()
        assert count >= 1
        assert cache.get("testpkg", None) is None


class TestThreatContextAggregation:
    def test_from_cves_computes_max_cvss(self):
        from guardian.threat_intel.models import CVERecord, FeedSource, ThreatContext
        cves = [
            CVERecord(cve_id="CVE-A", description="a", cvss_score=7.5, cvss_vector="", epss_score=0.5, severity="High", published="2023-01-01", modified="2023-01-01", source=FeedSource.NVD),
            CVERecord(cve_id="CVE-B", description="b", cvss_score=9.8, cvss_vector="", epss_score=0.9, severity="Critical", published="2023-01-01", modified="2023-01-01", source=FeedSource.NVD),
        ]
        ctx = ThreatContext.from_cves("pkg", "1.0", cves)
        assert ctx.max_cvss == 9.8
        assert ctx.max_epss == 0.9
        assert ctx.known_exploited_count == 0


class TestExcelAndCSVLoader:
    def test_load_xlsx_jira_stories(self, tmp_path):
        """Loads the actual Jira_User_Stories.xlsx from the project."""
        from guardian.compat_pandas import pd, PANDAS_AVAILABLE
        import pytest
        if not PANDAS_AVAILABLE:
            pytest.skip("pandas binary not available due to system policy")
        from guardian.intent.legacy.loader import RequirementLoader
        src = "/mnt/project/Jira_User_Stories.xlsx"
        if not Path(src).exists():
            pytest.skip(f"sample workbook not available: {src}")
        reqs = RequirementLoader().load(src)
        assert len(reqs) > 0
        assert reqs[0].source_id  # Story_ID populated
        assert reqs[0].content    # Business_Intent text populated
        assert reqs[0].acceptance_criteria  # AC column parsed into list

    def test_load_xlsx_column_mapping(self, tmp_path):
        """Excel with known Jira columns maps correctly."""
        from guardian.compat_pandas import pd, PANDAS_AVAILABLE
        import pytest
        if not PANDAS_AVAILABLE:
            pytest.skip("pandas binary not available due to system policy")
        from guardian.intent.legacy.loader import RequirementLoader
        df = pd.DataFrame([{
            "Story_ID": "US-001",
            "Title": "Loan approval",
            "Business_Intent": "Only managers can approve loans above 10 lakh.",
            "Acceptance_Criteria": "Role check required; amount validated; audit logged.",
            "Priority": "Critical",
            "Epic": "Epic",
            "Status": "To Do",
        }])
        f = tmp_path / "stories.xlsx"
        df.to_excel(f, sheet_name="UserStories", index=False)
        reqs = RequirementLoader().load(f)
        assert len(reqs) == 1
        assert reqs[0].source_id == "US-001"
        assert "manager" in reqs[0].content.lower()
        assert len(reqs[0].acceptance_criteria) >= 1

    def test_load_csv(self, tmp_path):
        """CSV with standard columns loads correctly."""
        from guardian.intent.legacy.loader import RequirementLoader
        f = tmp_path / "reqs.csv"
        f.write_text("id,title,description\nREQ-1,Auth,Only admins shall access settings.\n")
        reqs = RequirementLoader().load(f)
        assert len(reqs) == 1
        assert reqs[0].source_id == "REQ-1"

    def test_graceful_fallback_unknown_extension(self, tmp_path):
        """Unknown file extension falls back to plain text without crashing."""
        from guardian.intent.legacy.loader import RequirementLoader
        f = tmp_path / "spec.unknownext"
        f.write_text("Users must authenticate before accessing the dashboard.")
        reqs = RequirementLoader().load(f)
        assert len(reqs) == 1

    def test_xlsx_extracts_business_rules(self, tmp_path):
        """Rules are actually extracted from loaded Excel requirements."""
        from guardian.compat_pandas import pd, PANDAS_AVAILABLE
        import pytest
        if not PANDAS_AVAILABLE:
            pytest.skip("pandas binary not available due to system policy")
        from guardian.intent.legacy.loader import RequirementLoader
        from guardian.intent.legacy.extractor import RuleBasedExtractor
        df = pd.DataFrame([{
            "Story_ID": "US-999",
            "Title": "Settlement",
            "Business_Intent": "Only verified merchants may receive settlements.",
            "Acceptance_Criteria": "Merchant status must be verified; amount must be positive.",
            "Priority": "High",
            "Epic": "Payments",
            "Status": "Open",
        }])
        f = tmp_path / "test.xlsx"
        df.to_excel(f, sheet_name="UserStories", index=False)
        reqs = RequirementLoader().load(f)
        rules = RuleBasedExtractor().extract(reqs[0])
        assert len(rules) >= 1
        assert any("merchant" in r.actor.lower() or "merchant" in r.action.lower() for r in rules)
