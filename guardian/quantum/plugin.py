"""
Quantum Readiness — Analyzer adapter (policy-corrected).

Role separation, per the platform's two-lens crypto model:
  * The Security Rule Engine owns *classically broken* crypto (MD5, SHA-1,
    DES, ECB) as real, score-driving findings — that lens already works.
  * This analyzer owns the *quantum* lens: a complete Cryptographic Bill
    of Materials (CBOM), a readiness score, and a migration roadmap.

Policy decisions (from the Hyperswitch v6 audit, where the previous
adapter produced 384 findings — most of them regex false positives, the
rest legitimate-but-expected RSA/ECC usage that hard-blocked the merge):

  1. Shor-class usages (RSA / ECC / DSA / DH) are emitted as
     severity-Info findings, aggregated to ONE per (file, algorithm)
     with an occurrence count. They are visible in every report but do
     not drive the security risk score: using RSA today is not a
     present-day vulnerability, it is a migration-planning item.
  2. Hash/AES inventory (SHA-256, SHA-1, MD5, AES-128) never becomes a
     finding here — SHA-256 is industry standard, and broken hashes are
     already the Security Rule Engine's job. They remain fully visible
     in the CBOM.
  3. The readiness score + CBOM summary are exposed via `last_summary`
     for the report/dashboard layer, which is where quantum value
     actually lives.
  4. Merge gating on quantum findings is opt-in via
     GuardianConfig.enable_quantum_gate (see core/risk.py).
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer
from guardian.quantum.detector import QuantumDetector
from guardian.quantum.inventory import CryptoInventoryBuilder
from guardian.quantum.mapper import MigrationMapper

_SHOR_FAMILIES = {"RSA", "ECC", "DSA", "DIFFIE_HELLMAN"}
_SCANNABLE = {".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".kt", ".scala", ".conf"}


@register_analyzer
class QuantumReadinessAnalyzer:
    name = "quantum"

    def __init__(self) -> None:
        self._detector = QuantumDetector()
        self._cbom_builder = CryptoInventoryBuilder()
        self._mapper = MigrationMapper()
        self.last_cbom = None
        self.last_summary: Optional[dict] = None

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        usages = []
        for fp in files:
            if fp.suffix.lower() not in _SCANNABLE:
                continue
            try:
                usages.extend(self._detector.scan_file(fp))
            except OSError:
                continue

        # Full inventory: CBOM + summary (includes hashes, AES, TLS —
        # everything, because inventory must be complete even when the
        # findings list is deliberately quiet).
        self.last_cbom = self._cbom_builder.build(usages, target=str(repo_root))
        try:
            self.last_summary = self._cbom_builder.summary(self.last_cbom)
        except Exception:
            self.last_summary = None

        # Findings: Shor-class only, Info severity, one per (file, algorithm).
        grouped: dict[tuple[str, str], list] = defaultdict(list)
        for u in usages:
            family = getattr(u.family, "name", str(u.family)).upper()
            if family not in _SHOR_FAMILIES:
                continue
            grouped[(u.file, u.algorithm)].append(u)

        findings: list[Finding] = []
        for (file_path, algorithm), group in grouped.items():
            first = min(group, key=lambda u: u.line)
            mig = self._mapper.get_recommendation(algorithm)
            rec = (f"Replace with {mig.replacement_algorithm} ({mig.nist_standard}). {mig.rationale}"
                   if mig else
                   f"Plan migration of {algorithm} to a NIST PQC standard (FIPS 203/204/205).")
            try:
                label = str(Path(file_path).resolve().relative_to(Path(repo_root).resolve()))
            except (ValueError, OSError):
                label = file_path
            count_note = f" ({len(group)} usages in this file)" if len(group) > 1 else ""
            rec = rec[: 300 - len(count_note)] + count_note
            findings.append(Finding(
                category="Quantum Migration Inventory",
                severity="Info",
                rule_id=f"QNT-{algorithm.replace('/', '-').replace(' ', '')}",
                file=label,
                line=first.line,
                snippet=first.snippet[:200],
                recommendation=rec,
                confidence=0.85,
            ))
        return findings
