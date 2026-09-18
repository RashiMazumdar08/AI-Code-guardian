"""
Domain-agnostic Business Intent classifier.

Evidence sources (weighted):
    README / docs text          x3
    API spec paths/summaries    x3
    directory & package names   x2
    class/identifier tokens     x1

Output is a DomainVerdict: detected domain, confidence, alternatives,
and the concrete evidence supporting the verdict — so the answer is
always explainable and never a black box.

TODO(intent-roadmap): optional Nemotron re-ranking pass over the top-3
candidates using README context, gated behind config.enable_ai. The
legacy requirement-alignment engine (Excel/Jira user-story matching)
lives on unchanged in guardian.intent.legacy and is complementary:
this module answers "what domain IS this repo", legacy answers "does
the code match the stated requirements".
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from guardian.intent.domains import DOMAIN_KEYWORDS

log = logging.getLogger(__name__)

_WORD = re.compile(r"[A-Za-z][A-Za-z\-]{2,}")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass
class DomainVerdict:
    domain: str
    confidence: float                       # 0-1
    alternatives: list[tuple[str, float]] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)  # domain -> matched terms
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "confidence": round(self.confidence, 3),
            "alternatives": [(d, round(s, 3)) for d, s in self.alternatives],
            "evidence": self.evidence,
            "reasoning": self.reasoning,
        }


class DomainClassifier:
    DOC_WEIGHT, API_WEIGHT, PATH_WEIGHT, CODE_WEIGHT = 3, 3, 2, 1
    MAX_DOC_CHARS = 100_000
    MAX_CODE_FILES = 300

    def classify(self, repo_root: Path, files: list[Path] | None = None) -> DomainVerdict:
        repo_root = Path(repo_root)
        files = files if files is not None else [p for p in repo_root.rglob("*") if p.is_file()]

        weighted_tokens: Counter[str] = Counter()

        for fp in files:
            name = fp.name.lower()
            rel = str(fp).lower()
            # path/directory evidence
            for tok in _WORD.findall(rel):
                weighted_tokens[tok.lower()] += self.PATH_WEIGHT

            if name.startswith("readme") or fp.suffix.lower() in (".md", ".rst"):
                self._ingest_text(fp, weighted_tokens, self.DOC_WEIGHT)
            elif name in ("openapi.yaml", "openapi.yml", "openapi.json",
                          "swagger.yaml", "swagger.json") or "openapi" in name:
                self._ingest_text(fp, weighted_tokens, self.API_WEIGHT)

        # identifier evidence from a bounded sample of source files
        src = [f for f in files if f.suffix.lower() in (".java", ".py", ".js", ".ts", ".go", ".cs")]
        for fp in src[: self.MAX_CODE_FILES]:
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")[:20_000]
            except OSError:
                continue
            for ident in re.findall(r"\b(?:class|def|interface|func)\s+(\w+)", text):
                for tok in _CAMEL.split(ident):
                    weighted_tokens[tok.lower()] += self.CODE_WEIGHT

        scores: dict[str, float] = {}
        evidence: dict[str, list[str]] = {}
        for domain, keywords in DOMAIN_KEYWORDS.items():
            matched = {k: weighted_tokens[k] for k in keywords if weighted_tokens.get(k)}
            scores[domain] = float(sum(matched.values()))
            if matched:
                evidence[domain] = sorted(matched, key=matched.get, reverse=True)[:8]

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        top_domain, top_score = ranked[0]
        total = sum(s for _, s in ranked) or 1.0
        # Share-of-evidence, dampened by absolute evidence volume so a
        # single stray keyword can't produce a "100% confident" verdict.
        volume_factor = min(1.0, top_score / 50.0)
        confidence = (top_score / total) * volume_factor if top_score else 0.0

        if top_score == 0:
            return DomainVerdict(
                domain="Unclassified", confidence=0.0,
                reasoning="No domain-indicative vocabulary found in docs, paths, or identifiers.",
            )
        verdict = DomainVerdict(
            domain=top_domain,
            confidence=confidence,
            alternatives=[(d, s / total) for d, s in ranked[1:4] if s > 0],
            evidence={top_domain: evidence.get(top_domain, [])},
            reasoning=(
                f"Top evidence terms {evidence.get(top_domain, [])[:5]} matched the "
                f"'{top_domain}' vocabulary across docs, paths, and identifiers, "
                f"outscoring {len([s for _, s in ranked[1:] if s > 0])} alternative domains."
            ),
        )

        # Optional Nemotron AI re-ranking pass over top 3 candidate domains
        if verdict.alternatives:
            verdict = self._ai_rerank_pass(repo_root, verdict)

        return verdict

    def _ai_rerank_pass(self, repo_root: Path, verdict: DomainVerdict,
                        service=None) -> DomainVerdict:
        """Optionally re-rank the top candidates using the README.

        Routed through the shared reasoning service rather than building a
        client here. The previous implementation called `llm.complete()` and
        read `resp.text` — neither exists on `BaseLLM` — inside a bare
        `except`, so it failed silently on every run and no one could tell.

        The model may only re-order candidates the deterministic classifier
        already produced; it cannot introduce a domain, and any failure
        leaves the deterministic verdict untouched.
        """
        readme_text = ""
        for candidate in sorted(repo_root.glob("README*")):
            try:
                readme_text = candidate.read_text(errors="ignore")[:3000]
                break
            except OSError:
                continue
        if not readme_text:
            return verdict

        try:
            from guardian.reasoning.gateway import (
                NemotronReasoningService, ReasoningRequest,
            )
            from guardian.reasoning.schemas import extract_json

            service = service or NemotronReasoningService()
            if not service.configured:
                return verdict

            candidates = [verdict.domain] + [alt[0] for alt in verdict.alternatives]
            result = service.reason(ReasoningRequest(
                task="domain_classification",
                instruction=(
                    "Choose the primary business domain of this repository from "
                    "the CANDIDATES list. You may only choose from that list."),
                schema_instruction=(
                    'Return exactly one JSON object:\n'
                    '{"primary_domain": "<one of the candidates>", '
                    '"confidence": 0.0-1.0, "reasoning": "<one sentence>"}'),
                business_block="CANDIDATES:\n" + "\n".join(f"- {c}" for c in candidates),
                evidence_block="README:\n" + readme_text,
                system_role=("You classify repositories into business domains "
                             "using only the evidence provided."),
            ))
            if not result.available or result.response is None:
                return verdict

            data = extract_json(result.response.raw) or {}
            chosen = data.get("primary_domain")
            if chosen in candidates:
                verdict.domain = chosen
                try:
                    verdict.confidence = max(0.0, min(1.0, float(data.get(
                        "confidence", verdict.confidence))))
                except (TypeError, ValueError):
                    pass
                reasoning = str(data.get("reasoning", "")).strip()
                if reasoning:
                    verdict.reasoning += f" [AI re-ranked: {reasoning}]"
        except Exception as exc:  # noqa: BLE001 — classification must not fail a scan
            log.debug("domain re-ranking unavailable: %s", exc)
        return verdict

    def _ingest_text(self, fp: Path, tokens: Counter, weight: int) -> None:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")[: self.MAX_DOC_CHARS]
        except OSError:
            return
        for tok in _WORD.findall(text.lower()):
            tokens[tok] += weight

