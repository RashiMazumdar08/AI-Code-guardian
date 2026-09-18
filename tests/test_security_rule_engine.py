import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardian.scanner._engine import SecurityRuleEngine
from guardian.core.risk import compute_risk_report


def test_python_tainted_sql_injection_detected():
    engine = SecurityRuleEngine()
    src = """
def get_user(request):
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""
    findings = engine.scan_source(src, "app.py", language="python")
    cats = [f.category for f in findings]
    assert "SQL Injection" in cats
    assert any(f.tainted for f in findings)


def test_python_safe_query_not_flagged():
    engine = SecurityRuleEngine()
    src = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
"""
    findings = engine.scan_source(src, "app.py", language="python")
    assert not any(f.category == "SQL Injection" for f in findings)


def test_java_hardcoded_secret_camelcase_and_snake_case():
    engine = SecurityRuleEngine()
    src = 'String apiKey = "SECRET_KEY_1";\nString API_KEY = "SECRET_KEY_2";'
    findings = engine.scan_source(src, "Service.java", language="java")
    assert sum(1 for f in findings if f.category == "Hardcoded Secret") == 2


def test_java_constant_name_not_flagged_as_secret():
    engine = SecurityRuleEngine()
    src = 'public static final String SMTP_PASSWORD = "SMTP_PASSWORD";'
    findings = engine.scan_source(src, "Constants.java", language="java")
    assert not any(f.category == "Hardcoded Secret" for f in findings)


def test_java_trust_all_certs_detected():
    engine = SecurityRuleEngine()
    src = "X509TrustManager insecure = new X509TrustManager() {"
    findings = engine.scan_source(src, "Client.java", language="java")
    assert any(f.category == "Broken Authentication" for f in findings)


def test_finding_id_is_stable_for_dedup():
    engine = SecurityRuleEngine()
    src = 'String apiKey = "SECRET_KEY_1";'
    f1 = engine.scan_source(src, "Service.java", language="java")[0]
    f2 = engine.scan_source(src, "Service.java", language="java")[0]
    assert f1.finding_id == f2.finding_id


def test_risk_report_produces_merge_decision():
    engine = SecurityRuleEngine()
    src = 'String apiKey = "SECRET_KEY_1";'
    result = engine.scan_file.__wrapped__ if False else None  # placeholder no-op
    from guardian.core.models import ScanResult
    findings = engine.scan_source(src, "Service.java", language="java")
    sr = ScanResult(target="Service.java", files_scanned=1, findings=findings)
    risk = compute_risk_report(sr, alignment_score=90)
    assert 0 <= risk.security_score <= 100
    assert risk.merge_decision
