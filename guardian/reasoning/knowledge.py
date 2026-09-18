"""
RAG Knowledge Retrieval
=======================
Supplies the trusted domain knowledge a reasoning task needs — OWASP,
CWE, NIST SP 800-53, NIST PQC / FIPS 203-205, secure-coding guidance and
project-specific business requirements.

Two backends, in order:

  1. **The existing vector RAG** (`guardian.ai.retriever` over FAISS).
     Used when an index has been built and the embedding stack is
     installed. Retrieval is driven by the *evidence at hand*, not by the
     user's phrasing, so an RSA crypto evidence item pulls PQC migration
     guidance whether or not anyone typed "quantum".
  2. **A built-in knowledge pack** (`data/knowledge/*.json`), matched by
     topic keywords. This is not a stub: it is the curated set of
     standards text the reasoning prompts actually need, and it makes the
     AI layer useful on a machine with no FAISS, no embeddings and no
     network.

Whichever backend answers, the result is capped — the whole point is to
send a few hundred words of relevant standard, never a vector-store dump.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from guardian.evidence.models import Evidence, EvidenceType

log = logging.getLogger(__name__)

DEFAULT_KNOWLEDGE_DIR = (Path(__file__).resolve().parent.parent.parent
                         / "data" / "knowledge")

MAX_SNIPPETS = 4
MAX_SNIPPET_CHARS = 1200


@dataclass
class KnowledgeSnippet:
    """One retrieved piece of trusted knowledge."""

    id: str
    title: str
    content: str
    standard: str = ""
    score: float = 0.0
    origin: str = "builtin"      # "builtin" | "rag"

    def to_context_line(self) -> str:
        header = f"[{self.standard}] {self.title}" if self.standard else self.title
        return f"### {header}\n{self.content[:MAX_SNIPPET_CHARS]}"

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "standard": self.standard,
                "score": round(self.score, 3), "origin": self.origin}


# ---------------------------------------------------------------------------
# Query construction from evidence
# ---------------------------------------------------------------------------
#: Evidence tags/types -> extra retrieval terms. Retrieval follows the
#: evidence, which is what makes it grounded rather than keyword-driven.
_EVIDENCE_QUERY_TERMS: dict[EvidenceType, tuple[str, ...]] = {
    EvidenceType.TAINT_FLOW: ("injection", "input validation"),
    EvidenceType.CRYPTO_USAGE: ("cryptography",),
    EvidenceType.CRYPTO_DEPENDENCY: ("cryptography",),
    EvidenceType.SECRET: ("hardcoded secret", "credential"),
    EvidenceType.VULNERABLE_DEPENDENCY: ("dependency", "supply chain"),
    EvidenceType.IAC_MISCONFIGURATION: ("configuration", "hardening"),
    EvidenceType.MISSING_CONTROL: ("authorization", "approval", "access control"),
    EvidenceType.AUTHORIZATION_CHECK: ("authorization", "access control"),
    EvidenceType.BEHAVIOR: ("business rule", "authorization"),
    EvidenceType.BUSINESS_POLICY: ("business rule", "compliance"),
}

_QUANTUM_ALGORITHMS = {"RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH", "X25519", "Ed25519"}


def query_terms_for(evidence: Iterable[Evidence]) -> list[str]:
    """Derive retrieval terms from evidence rather than from prose."""
    terms: list[str] = []
    for item in evidence:
        terms.extend(_EVIDENCE_QUERY_TERMS.get(item.type, ()))
        terms.extend(t.split(":", 1)[-1] for t in item.tags if ":" in t)
        terms.extend(t for t in item.tags if ":" not in t)
        algorithm = (item.metadata or {}).get("algorithm", "")
        if algorithm:
            terms.append(algorithm)
            if algorithm in _QUANTUM_ALGORITHMS:
                terms.extend(("post-quantum", "pqc", "migration"))
        if item.operation:
            terms.append(item.operation)
    # de-duplicate, keep order
    seen: set[str] = set()
    out: list[str] = []
    for term in terms:
        key = term.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


# ---------------------------------------------------------------------------
# Built-in knowledge pack
# ---------------------------------------------------------------------------
class BuiltinKnowledgeBase:
    """Topic-keyword retrieval over the curated standards pack."""

    def __init__(self, knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR) -> None:
        self.entries: list[dict] = []
        self._load(knowledge_dir)

    def _load(self, knowledge_dir: Path) -> None:
        if not knowledge_dir.is_dir():
            log.warning("knowledge directory not found: %s", knowledge_dir)
            return
        for path in sorted(knowledge_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                log.warning("could not load knowledge file %s: %s", path, exc)
                continue
            if isinstance(data, list):
                self.entries.extend(e for e in data if isinstance(e, dict))

    def search(self, terms: Iterable[str], limit: int = MAX_SNIPPETS) -> list[KnowledgeSnippet]:
        term_list = [t.lower() for t in terms if t]
        if not term_list or not self.entries:
            return []

        scored: list[tuple[float, dict]] = []
        for entry in self.entries:
            topics = [str(t).lower() for t in entry.get("topics", [])]
            haystack = " ".join(topics + [str(entry.get("title", "")).lower()])
            score = 0.0
            for term in term_list:
                if term in topics:
                    score += 3.0            # exact topic hit
                    continue
                # Word-boundary only. Plain substring matching retrieves
                # path-traversal guidance for an "rsa" query, because
                # "traversal" contains "rsa".
                if re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", haystack):
                    score += 1.5
                elif len(term) > 5 and re.search(rf"(?<![\w-]){re.escape(term)}", haystack):
                    score += 0.75           # prefix match, e.g. "encrypt" -> "encryption"
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda pair: -pair[0])
        return [
            KnowledgeSnippet(
                id=entry.get("id", ""), title=entry.get("title", ""),
                content=entry.get("content", ""), standard=entry.get("standard", ""),
                score=score, origin="builtin")
            for score, entry in scored[:limit]
        ]


# ---------------------------------------------------------------------------
# Retriever facade
# ---------------------------------------------------------------------------
@dataclass
class RetrievalResult:
    snippets: list[KnowledgeSnippet] = field(default_factory=list)
    backend: str = "builtin"
    error: str = ""

    def render(self) -> str:
        return "\n\n".join(s.to_context_line() for s in self.snippets)

    def to_dict(self) -> dict:
        return {"backend": self.backend, "error": self.error,
                "snippets": [s.to_dict() for s in self.snippets]}


class KnowledgeRetriever:
    """Evidence-driven retrieval with vector RAG first, knowledge pack second."""

    def __init__(self, *, vector_retriever=None,
                 knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR,
                 enable_vector: bool = True) -> None:
        self._vector = vector_retriever
        self._enable_vector = enable_vector
        self._builtin = BuiltinKnowledgeBase(knowledge_dir)
        self._vector_failed = False

    # ------------------------------------------------------------------
    def retrieve_for_evidence(self, evidence: Iterable[Evidence],
                              *, extra_terms: Iterable[str] = (),
                              limit: int = MAX_SNIPPETS) -> RetrievalResult:
        terms = query_terms_for(evidence) + [t.lower() for t in extra_terms if t]
        return self.retrieve(terms, limit=limit)

    def retrieve(self, terms: Iterable[str], *, limit: int = MAX_SNIPPETS) -> RetrievalResult:
        """Retrieve trusted knowledge. Never raises — a RAG failure
        degrades to the built-in pack, and an empty result is fine."""
        term_list = [t for t in terms if t]
        if not term_list:
            return RetrievalResult(backend="none")

        if self._enable_vector and self._vector is not None and not self._vector_failed:
            try:
                snippets = self._vector_search(term_list, limit)
                if snippets:
                    return RetrievalResult(snippets=snippets, backend="rag")
            except Exception as exc:  # noqa: BLE001 — RAG outage is not a scan failure
                self._vector_failed = True
                log.warning("vector retrieval failed, using built-in knowledge: %s", exc)
                return RetrievalResult(
                    snippets=self._builtin.search(term_list, limit),
                    backend="builtin", error=str(exc))

        return RetrievalResult(snippets=self._builtin.search(term_list, limit),
                               backend="builtin")

    # ------------------------------------------------------------------
    def _vector_search(self, terms: list[str], limit: int) -> list[KnowledgeSnippet]:
        """Query the existing FAISS retriever with an evidence-derived query."""
        from guardian.ai.models import RAGQuery

        query = " ".join(dict.fromkeys(terms))[:400]
        result = self._vector.retrieve(RAGQuery(question=query, top_k=limit))
        snippets: list[KnowledgeSnippet] = []
        for chunk in getattr(result, "chunks", [])[:limit]:
            document = chunk.document
            snippets.append(KnowledgeSnippet(
                id=document.doc_id,
                title=document.source_path,
                content=document.content,
                standard=document.doc_type.value if hasattr(document.doc_type, "value")
                else str(document.doc_type),
                score=float(getattr(chunk, "similarity", 0.0)),
                origin="rag"))
        return snippets

    @property
    def backend_status(self) -> dict:
        return {
            "vector_enabled": bool(self._enable_vector and self._vector is not None),
            "vector_failed": self._vector_failed,
            "builtin_entries": len(self._builtin.entries),
        }


def build_default_retriever(*, enable_vector: bool = True,
                            config=None) -> KnowledgeRetriever:
    """Construct a retriever, wiring the FAISS backend when it is usable.

    Import failures (no numpy/faiss/sentence-transformers) are expected on
    a lean install and are not warnings — the built-in pack covers the
    standards the reasoning prompts need.
    """
    vector = None
    if enable_vector:
        try:
            from guardian.ai.config import AssistantConfig
            from guardian.ai.retriever import Retriever
            from guardian.ai.vector_store import FAISSVectorStore
            assistant_config = config or AssistantConfig()
            store = FAISSVectorStore(assistant_config)
            vector = Retriever(assistant_config, store)
        except Exception as exc:  # noqa: BLE001
            log.debug("vector RAG unavailable (%s); using built-in knowledge pack", exc)
            vector = None
    return KnowledgeRetriever(vector_retriever=vector, enable_vector=enable_vector)
