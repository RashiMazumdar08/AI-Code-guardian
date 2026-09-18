"""
Quantum Readiness — Layer A: UST Crypto Discovery
=================================================
Discovers cryptographic operations across every supported language by
reading the Unified Syntax Tree rather than grepping lines, then hands
each discovery to Layer B (`guardian.quantum.classification`) for a
deterministic verdict and CBOM aggregation.

Why UST and not keywords
------------------------
    // TODO: replace RSA with ML-KEM before 2030
A keyword scanner reports RSA usage here. The UST does not: a comment
produces no call node. Conversely

    Cipher.getInstance(props.get("cipher.suite"))
is a real crypto call whose algorithm we cannot resolve — the UST records
the call site and marks the algorithm unresolved, which is materially
different from "no crypto here" and from "RSA here".

Discovery sources, in order of strength:
  1. UST call/object-creation nodes tagged `crypto` (with the algorithm
     read from string-literal arguments where the API takes one);
  2. UST import nodes for crypto libraries (establishes the dependency
     even when call sites are dynamic);
  3. dependency evidence already in the store (crypto libraries declared
     in manifests), contributed by the SCA engine.

Layer C — contextual reasoning about purpose, business impact and
migration urgency — is NOT here. It lives in `guardian.reasoning` and
runs over this evidence, so Nemotron is never asked whether RSA exists.
"""
from __future__ import annotations

import logging
from typing import Optional

from guardian.core.context import AnalysisContext
from guardian.core.models import Finding, Severity
from guardian.engines.base import BaseEngine, EngineResult
from guardian.evidence.models import Evidence, EvidenceType
from guardian.quantum.classification import (
    CBOM, MIGRATION_REQUIRED, QuantumStatus, build_cbom, classify,
)
from guardian.reasoning.context import render_evidence, render_ust_context, select_for_crypto_asset
from guardian.reasoning.gateway import ReasoningRequest
from guardian.reasoning.schemas import QUANTUM_SCHEMA_INSTRUCTION
from guardian.reasoning.validation import AIFindingValidator, to_findings
from guardian.ust.models import USTFile, USTNode
from guardian.ust.tagging import CRYPTO_IMPORT_HINTS, resolve_algorithm

log = logging.getLogger(__name__)

ENGINE_NAME = "quantum"
DETECTOR = "ust_crypto_detector"

#: Dependency names that imply cryptography even without a call site.
CRYPTO_PACKAGE_HINTS = (
    "cryptography", "pycryptodome", "pycrypto", "rsa", "ecdsa", "pynacl",
    "bouncycastle", "bcprov", "bcpkix", "openssl", "ring", "rustls", "aws-lc",
    "node-forge", "crypto-js", "jsonwebtoken", "jose", "bcrypt", "argon2",
    "libsodium", "oqs", "liboqs", "tink", "nimbus-jose-jwt", "jjwt",
)


class QuantumReadinessEngine(BaseEngine):
    """Layer A discovery + Layer B classification + CBOM."""

    name = ENGINE_NAME

    def __init__(self, *, emit_findings: bool = True,
                 reasoning_service=None, knowledge_retriever=None,
                 use_llm: bool = True, max_reasoning_assets: int = 8) -> None:
        self.emit_findings = emit_findings
        self.service = reasoning_service
        self.knowledge = knowledge_retriever
        self.use_llm = use_llm
        self.max_reasoning_assets = max_reasoning_assets

    # ------------------------------------------------------------------
    def analyze(self, context: AnalysisContext) -> EngineResult:
        evidence: list[Evidence] = []

        for ust_file in context.ust:
            if not ust_file.nodes:
                continue
            try:
                evidence.extend(self._discover_in_file(ust_file))
            except Exception as exc:  # noqa: BLE001
                log.debug("crypto discovery failed for %s: %s", ust_file.path, exc)
                context.record_error(f"{self.name}:{ust_file.path}", exc)

        evidence.extend(self._discover_in_dependencies(context))

        # Publish before classifying so the CBOM can cite real evidence IDs.
        # `EvidenceStore.add` is idempotent by fingerprint, so the pipeline's
        # own publication pass in `run_engine` is a no-op for these items.
        evidence = [context.evidence.add(item) for item in evidence]

        # Layer B — deterministic classification into a CBOM.
        cbom = build_cbom(evidence, target=str(context.repository.root),
                          files_analyzed=len(context.ust.files))

        findings = self._inventory_findings(cbom, evidence) if self.emit_findings else []

        # Layer C — contextual reasoning about purpose, impact and migration
        # urgency. Nemotron is never asked *whether* RSA exists; Layer A has
        # already proved that. It is asked what this call site protects and
        # how urgent the migration is.
        ai_findings, ai_report = self._contextual_pass(context, evidence, cbom)
        findings.extend(ai_findings)
        cbom.contextual_analysis = ai_report

        return EngineResult(evidence=evidence, findings=findings, output=cbom)

    # ------------------------------------------------------------------
    # Layer A
    # ------------------------------------------------------------------
    def _discover_in_file(self, ust_file: USTFile) -> list[Evidence]:
        out: list[Evidence] = []
        confidence_penalty = 0.8 if ust_file.parser == "regex" else 1.0
        seen: set[tuple] = set()

        for node in ust_file.nodes:
            if not node.crypto_tags:
                continue

            if "crypto_import" in node.crypto_tags:
                item = self._import_evidence(node, ust_file, confidence_penalty)
                if item is not None:
                    out.append(item)
                continue

            if "crypto" not in node.crypto_tags:
                continue

            algorithm = _tag_value(node.crypto_tags, "algorithm")
            operation = _tag_value(node.crypto_tags, "operation")
            mode = _tag_value(node.crypto_tags, "mode")
            key = (ust_file.path, node.line, algorithm, operation)
            if key in seen:
                continue
            seen.add(key)

            classification = classify(algorithm)
            resolved = algorithm and algorithm != "unknown"

            out.append(Evidence(
                type=EvidenceType.CRYPTO_USAGE,
                source=DETECTOR,
                file=ust_file.path,
                line=node.line,
                end_line=node.span.end_line,
                column=node.column,
                language=ust_file.language,
                symbol=node.enclosing_function or node.enclosing_class or node.symbol,
                operation=(f"{algorithm} {operation}".strip() if resolved
                           else f"{operation or 'crypto'} with unresolved algorithm"),
                description=(
                    f"{node.symbol} performs {operation or 'a cryptographic operation'}"
                    + (f" using {algorithm}" if resolved else
                       " with an algorithm supplied at runtime")
                    + (f" in {mode} mode" if mode else "") + "."),
                snippet=node.snippet,
                confidence=round((1.0 if resolved else 0.6) * confidence_penalty, 2),
                severity_hint=_threat_to_severity(classification.status),
                node_id=node.node_id,
                tags=_crypto_evidence_tags(classification, mode),
                metadata={
                    "algorithm": algorithm or "unknown",
                    "operation": operation,
                    "mode": mode,
                    "api": node.symbol,
                    "status": classification.status.value,
                    "enclosing_function": node.enclosing_function,
                    "enclosing_class": node.enclosing_class,
                    "business_tags": node.business_tags,
                    "arguments": node.arguments[:4],
                    "resolved": bool(resolved),
                },
            ))
        return out

    def _import_evidence(self, node: USTNode, ust_file: USTFile,
                         penalty: float) -> Optional[Evidence]:
        algorithm = _tag_value(node.crypto_tags, "algorithm")
        classification = classify(algorithm) if algorithm else None
        return Evidence(
            type=EvidenceType.CRYPTO_DEPENDENCY,
            source=DETECTOR,
            file=ust_file.path,
            line=node.line,
            language=ust_file.language,
            symbol=node.name,
            operation=f"cryptographic library import: {node.name}",
            description=f"{ust_file.path} imports the cryptographic module '{node.name}'.",
            snippet=node.snippet,
            confidence=round(0.9 * penalty, 2),
            node_id=node.node_id,
            tags=["crypto", "crypto_import"] + (
                [f"algorithm:{algorithm}"] if algorithm else []),
            metadata={"module": node.name,
                      "algorithm": algorithm or "",
                      "status": classification.status.value if classification else ""},
        )

    def _discover_in_dependencies(self, context: AnalysisContext) -> list[Evidence]:
        """Crypto libraries declared in manifests, via SCA evidence already
        in the store. Establishes crypto presence in a repository whose
        call sites we could not parse."""
        out: list[Evidence] = []
        for item in context.evidence.by_type(EvidenceType.DEPENDENCY,
                                             EvidenceType.VULNERABLE_DEPENDENCY):
            package = str((item.metadata or {}).get("package") or item.symbol or "").lower()
            if not package:
                continue
            if not any(hint in package for hint in CRYPTO_PACKAGE_HINTS):
                continue
            algorithm = resolve_algorithm(package)
            out.append(Evidence(
                type=EvidenceType.CRYPTO_DEPENDENCY,
                source=DETECTOR,
                file=item.file,
                line=item.line,
                language=item.language,
                symbol=package,
                operation=f"cryptographic dependency: {package}",
                description=f"The manifest declares the cryptographic library '{package}'.",
                confidence=0.8,
                tags=["crypto", "dependency"] + ([f"algorithm:{algorithm}"] if algorithm else []),
                metadata={"package": package, "algorithm": algorithm or "",
                          "from_evidence": item.id},
            ))
        return out

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def _inventory_findings(self, cbom: CBOM, evidence: list[Evidence]) -> list[Finding]:
        """Emit migration-inventory findings.

        Policy preserved from the previous adapter (Hyperswitch audit):
        Shor-class usage is *inventory*, not a present-day vulnerability.
        Findings are Info severity, aggregated to one per (file,
        algorithm), and never drive the security score. Merge gating stays
        opt-in via `GuardianConfig.enable_quantum_gate`.
        """
        by_location: dict[tuple[str, str], list[Evidence]] = {}
        for item in evidence:
            if item.type is not EvidenceType.CRYPTO_USAGE:
                continue
            algorithm = (item.metadata or {}).get("algorithm", "unknown")
            status = classify(algorithm).status
            if status not in MIGRATION_REQUIRED:
                continue
            by_location.setdefault((item.file, algorithm), []).append(item)

        findings: list[Finding] = []
        for (file_path, algorithm), group in by_location.items():
            first = min(group, key=lambda e: e.line)
            classification = classify(algorithm)
            count_note = f" ({len(group)} usages in this file)" if len(group) > 1 else ""
            recommendation = (
                f"Migrate to {classification.migration_target}"
                f"{f' ({classification.nist_standard})' if classification.nist_standard else ''}. "
                f"{classification.rationale}")[:300 - len(count_note)] + count_note

            findings.append(Finding(
                category="Quantum Migration Inventory",
                severity=Severity.INFO.value,
                rule_id=f"QNT-{algorithm.replace('/', '-').replace(' ', '')}",
                file=file_path,
                line=first.line,
                snippet=first.snippet[:200],
                recommendation=recommendation,
                cwe="CWE-327",
                owasp="A02:2021",
                confidence=first.confidence,
                language=first.language,
                function=(first.metadata or {}).get("enclosing_function", ""),
                evidence_ids=[e.id for e in group if e.id],
                source="DETERMINISTIC",
                reason=(f"{algorithm} is {classification.status.value.replace('_', ' ')}: "
                        f"{classification.rationale}"),
                engine=self.name,
            ))
        return sorted(findings, key=lambda f: (f.file, f.line))


    # ------------------------------------------------------------------
    # Layer C — contextual reasoning
    # ------------------------------------------------------------------
    def _contextual_pass(self, context: AnalysisContext, evidence: list[Evidence],
                         cbom: CBOM) -> tuple[list[Finding], dict]:
        if not self.use_llm or self.service is None:
            return [], {"status": "skipped", "reason": "contextual analysis disabled"}
        if not self.service.configured:
            return [], {"status": "unavailable",
                        "reason": self.service.unavailable_reason()}

        # Only assets that need a migration decision are worth a model call.
        candidates = [
            item for item in evidence
            if item.type is EvidenceType.CRYPTO_USAGE
            and classify((item.metadata or {}).get("algorithm", "")).status
            in MIGRATION_REQUIRED
        ]
        if not candidates:
            return [], {"status": "no_candidates"}

        # Prioritise assets that look business-critical, then by confidence.
        candidates.sort(key=lambda e: (
            0 if (e.metadata or {}).get("business_tags") else 1, -e.confidence))
        candidates = candidates[: self.max_reasoning_assets]

        findings, reports = [], []
        for item in candidates:
            asset_findings, report = self._reason_about_asset(context, item)
            findings.extend(asset_findings)
            reports.append(report)

        return findings, {"status": "analyzed", "assets_analyzed": len(reports),
                          "reports": reports}

    def _reason_about_asset(self, context: AnalysisContext,
                            crypto: Evidence) -> tuple[list[Finding], dict]:
        selected = select_for_crypto_asset(context, crypto)
        metadata = crypto.metadata or {}
        algorithm = metadata.get("algorithm", "unknown")
        classification = classify(algorithm)

        knowledge_block, knowledge_meta = "", {}
        if self.knowledge is not None:
            retrieval = self.knowledge.retrieve_for_evidence(
                selected, extra_terms=[algorithm, "post-quantum", "migration"])
            knowledge_block = retrieval.render()
            knowledge_meta = retrieval.to_dict()

        ust_block = render_ust_context(
            context.ust_file(crypto.file), around_line=crypto.line,
            function_name=metadata.get("enclosing_function", ""))

        request = ReasoningRequest(
            task="quantum_readiness",
            instruction=(
                f"A deterministic scan has already PROVEN that {algorithm} is used at "
                f"{crypto.file}:{crypto.line} ({metadata.get('api', '')}). Do not "
                f"re-assess whether it exists.\n\n"
                f"Deterministic classification: {classification.status.value} — "
                f"{classification.rationale}\n"
                f"Standard migration target: {classification.migration_target}"
                f"{f' ({classification.nist_standard})' if classification.nist_standard else ''}\n\n"
                "Assess only the CONTEXT: what this cryptographic operation protects, "
                "the business and security impact of it being broken, how urgent "
                "migration is given the likely lifetime of the protected data, which "
                "component is affected, and a concrete migration approach for this "
                "specific call site. Use only the evidence and code structure below."),
            schema_instruction=QUANTUM_SCHEMA_INSTRUCTION,
            evidence_block=render_evidence(selected),
            knowledge_block=knowledge_block,
            ust_block=ust_block,
            cache_key_extra=f"{crypto.file}:{crypto.line}:{algorithm}",
        )

        result = self.service.reason(request)
        report = {
            "evidence_id": crypto.id,
            "algorithm": algorithm,
            "file": crypto.file,
            "line": crypto.line,
            "available": result.available,
            "error": result.error,
            "cached": result.cached,
            "prompt_chars": result.prompt_chars,
            "knowledge": knowledge_meta,
        }
        if not result.available or result.response is None:
            report["status"] = "unavailable"
            return [], report

        validator = AIFindingValidator(
            context, allowed_evidence={e.id for e in selected if e.id})
        validation = validator.validate_response(result.response)
        report["status"] = "analyzed"
        report["validation"] = validation.to_dict()

        for item in validation.accepted:
            item.category = "Quantum Readiness"
            item.metadata.setdefault("algorithm", algorithm)
            item.metadata.setdefault("classification", classification.status.value)
            # The deterministic policy stands: crypto inventory is a
            # migration item, not a live vulnerability. A model may raise
            # migration urgency; it may not promote inventory into a
            # present-day High/Critical security finding.
            item.severity = Severity.INFO.value

        return (to_findings(validation.accepted, engine=self.name,
                            default_category="Quantum Readiness"), report)


# ---------------------------------------------------------------------------
def _tag_value(tags: list[str], key: str) -> str:
    prefix = key + ":"
    for tag in tags:
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return ""


def _crypto_evidence_tags(classification, mode: str) -> list[str]:
    tags = ["crypto", f"algorithm:{classification.algorithm}",
            f"status:{classification.status.value}"]
    if classification.status is QuantumStatus.VULNERABLE:
        tags.append("quantum_vulnerable")
    elif classification.status is QuantumStatus.PQC:
        tags.append("pqc")
    elif classification.status is QuantumStatus.BROKEN:
        tags.append("classically_broken")
    if mode:
        tags.append(f"mode:{mode}")
    return tags


def _threat_to_severity(status: QuantumStatus) -> str:
    return {
        QuantumStatus.VULNERABLE: Severity.INFO.value,   # inventory, per policy
        QuantumStatus.BROKEN: Severity.HIGH.value,
        QuantumStatus.WEAKENED: Severity.LOW.value,
        QuantumStatus.UNKNOWN: Severity.LOW.value,
        QuantumStatus.SAFE: Severity.INFO.value,
        QuantumStatus.PQC: Severity.INFO.value,
    }.get(status, Severity.INFO.value)
