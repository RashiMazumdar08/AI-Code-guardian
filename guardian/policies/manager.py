"""
AI Code Guardian v3 — Policy Pack Manager
========================================
Manages policy pack registration, organization profiles, rule evaluation, and versioning.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.policies.loader import PolicyLoader
from guardian.policies.schema import PolicyPack, PolicyRule

logger = logging.getLogger(__name__)


class PolicyPackManager:
    """Central manager for policy packs, organization profiles, and rule evaluation."""

    def __init__(self) -> None:
        self.loader = PolicyLoader()
        self._packs: Dict[str, PolicyPack] = {}
        self.register_default_policies()

    def register_default_policies(self) -> None:
        """Registers built-in default compliance policy packs (OWASP, NIST, PCI-DSS)."""
        owasp_pack = PolicyPack(
            name="OWASP_TOP_10",
            version="2021.1",
            description="OWASP Top 10 Security Policy Controls",
            rules=[
                PolicyRule("POL-OWASP-A01", "Broken Access Control", "HIGH", "access_control"),
                PolicyRule("POL-OWASP-A02", "Cryptographic Failures", "HIGH", "crypto"),
                PolicyRule("POL-OWASP-A03", "Injection Prevention", "CRITICAL", "injection"),
            ],
        )
        nist_pack = PolicyPack(
            name="NIST_800_53",
            version="rev5",
            description="NIST SP 800-53 Security and Privacy Controls",
            rules=[
                PolicyRule("POL-NIST-AC", "Access Control Management", "HIGH", "access_control"),
                PolicyRule("POL-NIST-SC", "System and Communications Protection", "MEDIUM", "network"),
            ],
        )
        self.register_pack(owasp_pack)
        self.register_pack(nist_pack)

    def register_pack(self, pack: PolicyPack) -> None:
        """Register a policy pack."""
        self._packs[pack.name] = pack

    def load_and_register(self, file_path: Path) -> Optional[PolicyPack]:
        """Loads policy pack from file and registers it."""
        pack = self.loader.load_from_file(file_path)
        if pack:
            self.register_pack(pack)
        return pack

    def get_pack(self, name: str) -> Optional[PolicyPack]:
        """Retrieves a registered policy pack by name."""
        return self._packs.get(name)

    def list_packs(self) -> List[str]:
        """Lists all registered policy pack names."""
        return list(self._packs.keys())

    def evaluate_findings(
        self,
        findings: List[Dict[str, Any]],
        active_pack_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Evaluates findings against active policy packs."""
        active_packs = [self._packs[p] for p in (active_pack_names or self.list_packs()) if p in self._packs]

        violations: List[Dict[str, Any]] = []
        passed: List[str] = []
        failed: List[str] = []

        for pack in active_packs:
            pack_failed = False
            for rule in pack.rules:
                matching_findings = [f for f in findings if rule.category.lower() in f.get("category", "").lower() or rule.rule_id in f.get("rule_id", "")]
                if matching_findings:
                    pack_failed = True
                    for mf in matching_findings:
                        violations.append({
                            "policy_name": pack.name,
                            "rule_id": rule.rule_id,
                            "rule_name": rule.name,
                            "severity": rule.severity,
                            "finding_id": mf.get("finding_id", ""),
                            "description": mf.get("description", rule.description),
                        })

            if pack_failed:
                failed.append(pack.name)
            else:
                passed.append(pack.name)

        return {
            "total_violations": len(violations),
            "violations": violations,
            "passed_policies": passed,
            "failed_policies": failed,
            "overrides": [],
        }
