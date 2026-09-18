"""
Threat Intelligence Engine — Normalizer
=========================================
Normalises raw CVERecord objects:
- Fills in OWASP Top 10 categories from CWE mappings
- Fills in MITRE ATT&CK IDs from CWE mappings (best-effort)
- Cleans severity labels to a consistent vocabulary
- Derives CVSS severity when score is present but label is generic

All mappings live here; future updates require editing this file only.
"""
from __future__ import annotations

from guardian.threat_intel.models import CVERecord

# CWE → OWASP Top 10 2021 category
_CWE_TO_OWASP: dict[str, str] = {
    "CWE-89": "A03:2021-Injection",
    "CWE-564": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",        # XSS
    "CWE-78": "A03:2021-Injection",        # Command Injection
    "CWE-88": "A03:2021-Injection",
    "CWE-918": "A10:2021-SSRF",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-284": "A01:2021-Broken Access Control",
    "CWE-285": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-306": "A07:2021-Identification and Authentication Failures",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-259": "A07:2021-Identification and Authentication Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-311": "A02:2021-Cryptographic Failures",
    "CWE-319": "A02:2021-Cryptographic Failures",
    "CWE-434": "A04:2021-Insecure Design",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-611": "A05:2021-Security Misconfiguration",
    "CWE-1395": "A06:2021-Vulnerable and Outdated Components",
    "CWE-532": "A09:2021-Security Logging and Monitoring Failures",
}

# CWE → representative MITRE ATT&CK Technique ID
_CWE_TO_MITRE: dict[str, str] = {
    "CWE-89": "T1190",   # Exploit Public-Facing Application
    "CWE-79": "T1059.007",  # JavaScript / XSS
    "CWE-78": "T1059",   # Command and Scripting Interpreter
    "CWE-287": "T1078",  # Valid Accounts (auth bypass)
    "CWE-798": "T1078.001",  # Hardcoded credentials
    "CWE-22": "T1083",   # File and Directory Discovery / traversal
    "CWE-502": "T1059",  # Deserialization → code exec
    "CWE-918": "T1090",  # Proxy via SSRF
    "CWE-327": "T1573",  # Encrypted Channel (weak crypto)
}

_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "none": "Info",
}


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0.0:  return "Low"
    return "Info"


class CVENormalizer:
    """
    Stateless normaliser — safe to call concurrently.
    """

    def normalize(self, cve: CVERecord) -> CVERecord:
        # 1. Canonicalize severity
        normalised_sev = _SEVERITY_ALIASES.get(cve.severity.lower(), cve.severity)
        if cve.cvss_score > 0 and normalised_sev in ("Info", ""):
            normalised_sev = _cvss_to_severity(cve.cvss_score)
        cve.severity = normalised_sev

        # 2. Add OWASP categories from CWE
        for cwe in cve.cwe_ids:
            owasp = _CWE_TO_OWASP.get(cwe)
            if owasp and owasp not in cve.owasp_categories:
                cve.owasp_categories.append(owasp)

        # 3. Add MITRE ATT&CK IDs from CWE
        for cwe in cve.cwe_ids:
            mitre = _CWE_TO_MITRE.get(cwe)
            if mitre and mitre not in cve.mitre_attack_ids:
                cve.mitre_attack_ids.append(mitre)

        return cve

    def normalize_many(self, cves: list[CVERecord]) -> list[CVERecord]:
        return [self.normalize(c) for c in cves]
