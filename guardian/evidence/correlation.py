"""
AI Code Guardian v3 — Evidence Correlation Service
==================================================
Correlates security findings, knowledge graph topology, business intent, policies,
and threat context to build attack chains and deduplicated evidence chains.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class EvidenceCorrelationService:
    """Service correlating findings, evidence objects, business assets, and attack chains."""

    def correlate(
        self,
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        business_context: Optional[Dict[str, Any]] = None,
        threat_context: Optional[Dict[str, Any]] = None,
        policy_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Deduplicates findings, correlates evidence, and builds structured attack chains."""
        business_context = business_context or {}
        threat_context = threat_context or {}
        policy_results = policy_results or {}

        # 1. Deduplicate Findings by rule_id, file_path, and line_number
        seen_keys = set()
        dedup_findings: List[Dict[str, Any]] = []
        for f in findings:
            key = (f.get("rule_id", ""), f.get("file_path", ""), f.get("line_number", 0))
            if key not in seen_keys:
                seen_keys.add(key)
                dedup_findings.append(f)

        # 2. Map evidence to findings
        evidence_map: Dict[str, List[str]] = {}
        for ev in evidence:
            f_id = ev.get("finding_id", "")
            ev_id = ev.get("evidence_id", "")
            if f_id and ev_id:
                if f_id not in evidence_map:
                    evidence_map[f_id] = []
                evidence_map[f_id].append(ev_id)

        # 3. Build Attack Chains
        raw_paths = threat_context.get("attack_paths", [])
        attack_chains: List[Dict[str, Any]] = []

        for idx, path in enumerate(raw_paths):
            f_id = path.get("finding_id", "")
            associated_evidence = evidence_map.get(f_id, [path.get("evidence_id", "")])
            chain = {
                "chain_id": f"chain-{idx+1}",
                "title": path.get("title", f"Attack Chain {idx+1}"),
                "finding_id": f_id,
                "evidence_ids": associated_evidence,
                "target_asset": path.get("entry_point", "public_api"),
                "business_criticality": business_context.get("criticality", "NORMAL"),
                "policy_violations": [v.get("rule_id") for v in policy_results.get("violations", []) if v.get("finding_id") == f_id],
                "exploitability": path.get("exploitability", 0.5),
            }
            attack_chains.append(chain)

        return {
            "total_correlated": len(dedup_findings),
            "deduplicated_findings": dedup_findings,
            "chains": attack_chains,
            "evidence_mapping": evidence_map,
        }
