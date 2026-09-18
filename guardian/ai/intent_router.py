"""
AI Code Guardian — Chatbot Intent Routing
===========================================
Classifies each incoming chat question into one of three intents before
it reaches the RAG pipeline (guardian/ai/rag_pipeline.py), so the pipeline
can decide how much repository-specific grounding a question actually
calls for, instead of always running the exact same retrieval+grounding
path regardless of what was asked.

    GENERAL_SECURITY -- a general security/programming knowledge question
        with no reference to "this" repository, scan, or codebase (e.g.
        "what is SQL injection?", "how does OAuth2 work?"). Answered from
        the LLM's own knowledge; scan-report exact-match grounding is
        skipped so nothing from an unrelated repository can leak into an
        answer that was never about it.
    REPOSITORY -- specifically about the indexed repository/scan (names a
        real finding_id/rule_id/file from the current report, or uses
        repo-referential language like "my code"/"this repo"/"our scan").
        Full grounding (exact_match_context + retrieval + validation)
        always runs -- exactly today's unconditional behavior.
    MIXED -- both signals present, or the question is genuinely ambiguous.
        Also the safe default when neither signal is clearly present --
        MIXED runs the full grounding path (today's unconditional
        behavior), so an unclassifiable question never silently loses
        grounding it might have needed.

This is a deterministic, regex/keyword classifier -- NOT an LLM call. An
LLM-based classifier would add latency and its own hallucination surface
to a step whose only job is deciding how much grounding to fetch; the
literal, mechanical signals used here (does the question actually name
something from the report, or use repo-referential language) match the
kind of check the rest of this pipeline already prefers -- see
guardian/ai/scan_context.py's exact_match_context(): deterministic
lookup, returns "" rather than guessing when nothing matches.

The ONLY behavior this routing changes is whether exact_match_context()
gets skipped for a confidently GENERAL_SECURITY question (see
RAGPipeline.ask/ask_stream in guardian/ai/rag_pipeline.py) -- retrieval,
the system prompt's own "don't invent repo specifics" instruction, and
ResponseValidator's mechanical hallucination check are unchanged and
still run for every question, regardless of classification.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from guardian.ai.scan_context import exact_match_context

__all__ = ["ChatIntent", "classify_intent"]


class ChatIntent(str, Enum):
    GENERAL_SECURITY = "GENERAL_SECURITY"
    REPOSITORY = "REPOSITORY"
    MIXED = "MIXED"


# Repo-referential language: the question is asking about THIS indexed
# repository/scan, even without literally naming one of its findings.
_REPO_REFERENTIAL = re.compile(
    r"\b(my|our|this|the)\s+(repo|repository|code\s?base|"
    r"project|scan|findings?|application|app|service)\b"
    r"|\bmy\s+code\b|\bour\s+code\b"
    r"|\b(in|from|within)\s+my\s+(code|repo|files?)\b",
    re.I,
)

# Generic "explain a concept" phrasing typically used for textbook-style
# security/programming questions rather than a question about a specific
# scan result.
_GENERIC_EXPLAIN = re.compile(
    r"^\s*(what\s+is|what\s+are|how\s+does|how\s+do|explain|define|"
    r"what's\s+the\s+difference\s+between|why\s+is|why\s+does)\b",
    re.I,
)


def classify_intent(question: str, scan_report: Optional[dict] = None) -> ChatIntent:
    """Real, deterministic classification -- never a guess dressed up as
    one. Prefers MIXED (today's default full-grounding behavior) whenever
    the signals are ambiguous or absent, so misclassifying never means
    silently dropping grounding a repo-specific question needed."""
    if not question or not question.strip():
        return ChatIntent.MIXED

    has_exact_match = bool(exact_match_context(question, scan_report))
    has_repo_language = bool(_REPO_REFERENTIAL.search(question))
    is_generic_explain = bool(_GENERIC_EXPLAIN.match(question.strip()))

    if has_exact_match:
        # The strongest possible signal: the question literally names a
        # real rule_id/finding_id/file from THIS report. Wins outright,
        # regardless of phrasing -- "what is SEC-001?" is unambiguously
        # about the repository, not a generic textbook "what is" question.
        return ChatIntent.REPOSITORY
    if has_repo_language and is_generic_explain:
        # e.g. "explain the SQL injection risk in my code" -- a generic
        # concept-explain phrasing AND a (non-exact) repo reference.
        return ChatIntent.MIXED
    if has_repo_language:
        return ChatIntent.REPOSITORY
    if is_generic_explain:
        return ChatIntent.GENERAL_SECURITY
    # No confident signal either way -- default to MIXED, not GENERAL, so
    # a repo-specific question phrased unusually never loses grounding.
    return ChatIntent.MIXED
