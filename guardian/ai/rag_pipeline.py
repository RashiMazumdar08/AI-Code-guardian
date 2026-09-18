"""
AI Code Guardian — RAG Pipeline
==================================
End-to-end pipeline:

    Question
      → RAGQuery
      → Retriever.retrieve()   (FAISS search, context merge)
      → PromptBuilder.build()  (structured prompt)
      → BaseLLM.chat()         (LLM generation, provider-agnostic)
      → AssistantResponse      (answer + citations + grounding flag)

Also provides a streaming variant for Streamlit token-by-token rendering.

Evaluation
----------
When config.eval_enabled is True, each response is logged to eval_log.jsonl
with metrics: retrieval_count, grounded, latency_ms.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Generator, Optional

from guardian.ai.config import AssistantConfig
from guardian.ai.conversation_memory import ConversationMemory
from guardian.ai.intent_router import ChatIntent, classify_intent
from guardian.ai.scan_context import exact_match_context
from guardian.ai.validator import ResponseValidator
from guardian.ai.models import (
    AssistantResponse, ChatMessage, MessageRole, RAGQuery, RAGResult,
)
from guardian.llm.base import BaseLLM, LLMError
from guardian.ai.prompt_builder import PromptBuilder
from guardian.ai.retriever import Retriever

logger = logging.getLogger(__name__)

_NOT_FOUND_MARKER = "I could not find evidence in the indexed repository"


import re

_GREETING_PATTERNS = {
    re.compile(r"^(h[iaeo]+|greetings|good\s+(morning|afternoon|evening))\b[\!\?\. ]*$", re.I):
        "Hello! I am your AI Security Copilot. How can I help you with your repository security scan or code review today?",
    re.compile(r"^(who\s+are\s+you|what\s+can\s+you\s+do|help|what\s+is\s+this)\b[\!\?\. ]*$", re.I):
        "I am your AI Code Guardian Assistant! I can help explain security vulnerabilities, risk scores, post-quantum crypto risks, and business intent findings.",
    re.compile(r"^(thanks|thank\s+you|thx|awesome|great|cool)\b[\!\?\. ]*$", re.I):
        "You're welcome! Let me know if you have any more questions about your codebase.",
    re.compile(r"^(bye|goodbye|cya|see\s+you)\b[\!\?\. ]*$", re.I):
        "Goodbye! Have a great day.",
}


def _get_conversational_response(question: str) -> Optional[str]:
    q = question.strip()
    for pat, resp in _GREETING_PATTERNS.items():
        if pat.match(q):
            return resp
    return None


class RAGPipeline:
    """
    The central coordinator. Inject all sub-components for testability.
    """

    def __init__(
        self,
        config: AssistantConfig,
        llm: BaseLLM,
        retriever: Retriever,
        prompt_builder: PromptBuilder,
        memory: ConversationMemory,
    ):
        self._cfg     = config
        self._llm     = llm
        self._retriever = retriever
        self._builder   = prompt_builder
        self._memory    = memory
        # Grounding + validation state (set via attach_scan_context)
        self._scan_report: dict | None = None
        self._validator: ResponseValidator | None = None

    def attach_scan_context(self, scan_report: dict | None = None,
                            repo_root: str | None = None) -> None:
        """Attach a scan report + repo root: enables exact-match finding
        injection and mechanical answer validation."""
        self._scan_report = scan_report
        self._validator = ResponseValidator(repo_root=repo_root,
                                            scan_report=scan_report)

    # ------------------------------------------------------------------
    # Non-streaming
    # ------------------------------------------------------------------

    def ask(self, question: str, top_k: Optional[int] = None) -> AssistantResponse:
        """
        Ask a question and return a complete AssistantResponse.
        Records the turn in conversation memory.
        """
        t0 = time.time()

        # Fast path for casual greetings & conversational pleasantries
        conv_resp = _get_conversational_response(question)
        if conv_resp:
            response = AssistantResponse(
                answer=conv_resp, citations=[], grounded=True,
                chunks_used=[], latency_ms=round((time.time() - t0) * 1000, 1),
                intent="CONVERSATIONAL")
            self._memory.add_user_message(question)
            self._memory.add_assistant_message(response)
            return response

        # Intent routing (v2.1.0 Part 32): a deterministic classification,
        # not an LLM call -- see guardian/ai/intent_router.py. The only
        # behavior this changes is skipping exact_match_context() below for
        # a confidently GENERAL_SECURITY question, so scan-report specifics
        # from a potentially unrelated repository never get injected into
        # an answer that was never about this repository. Retrieval, the
        # system prompt's own grounding instructions, and ResponseValidator
        # still run unconditionally for every question.
        intent = classify_intent(question, self._scan_report)

        rag_query = RAGQuery(
            question=question,
            top_k=top_k or self._cfg.retrieval_top_k,
        )
        rag_result = self._retriever.retrieve(rag_query)
        exact_ctx = ("" if intent is ChatIntent.GENERAL_SECURITY
                     else exact_match_context(question, self._scan_report))

        # No hard pre-LLM refusal here: with nothing indexed yet, a general
        # knowledge question ("what is SQL injection?") should still get a
        # real answer, not a canned "no evidence" reply before the model
        # is even asked. The system prompt (PromptBuilder) instructs the
        # LLM to answer general questions from its own knowledge while
        # refusing to invent repo-specific files/lines/findings, and the
        # ResponseValidator below still catches any unverifiable specific
        # reference after the fact — so this stays as safe as a hard
        # refusal for repo-specific claims, without blocking everything
        # else when no scan/documents have been loaded yet.
        if exact_ctx:
            rag_result.merged_context = exact_ctx + "\n\n" + rag_result.merged_context

        messages   = self._builder.build(
            question=question,
            rag_result=rag_result,
            history=self._memory.get_history(),
            repo_summary=self._memory.context.repo_summary,
        )

        try:
            raw_answer = self._llm.chat(messages).content
        except LLMError as exc:
            raw_answer = f"⚠️ LLM error: {exc}\n\nCheck NVIDIA_API_KEY and network connectivity."

        latency = (time.time() - t0) * 1000
        grounded = _NOT_FOUND_MARKER not in raw_answer and (bool(rag_result.chunks) or bool(exact_ctx))

        # Mechanical hallucination check (Master Design Doc §9.1):
        # unverifiable file/line/rule references demote the answer to
        # ungrounded and append an explicit warning for the user.
        if self._validator is not None:
            verdict = self._validator.validate(raw_answer)
            if not verdict.ok:
                raw_answer += verdict.warning_block()
                grounded = False

        response = AssistantResponse(
            answer=self._append_citations(raw_answer, rag_result.citations, grounded),
            citations=rag_result.citations,
            grounded=grounded,
            chunks_used=rag_result.chunks,
            latency_ms=round(latency, 1),
            intent=intent.value,
        )

        # Record in memory
        self._memory.add_user_message(question)
        self._memory.add_assistant_message(response)

        if self._cfg.eval_enabled:
            self._log_eval(question, rag_result, response)

        return response

    # ------------------------------------------------------------------
    # Streaming (for Streamlit st.write_stream)
    # ------------------------------------------------------------------

    def ask_stream(
        self,
        question: str,
        top_k: Optional[int] = None,
    ) -> Generator[str, None, None]:
        """
        Streaming version — yields token strings.
        Memory is updated after the generator is exhausted.
        """
        t0 = time.time()

        # Fast path for casual greetings & conversational pleasantries
        conv_resp = _get_conversational_response(question)
        if conv_resp:
            self._memory.add_user_message(question)
            self._memory.add_assistant_text(conv_resp, [])
            yield conv_resp
            return

        # Intent routing — see the matching comment in ask() above and
        # guardian/ai/intent_router.py. Same rule here: only a confidently
        # GENERAL_SECURITY question skips exact_match_context().
        intent = classify_intent(question, self._scan_report)

        rag_query = RAGQuery(
            question=question,
            top_k=top_k or self._cfg.retrieval_top_k,
        )
        rag_result = self._retriever.retrieve(rag_query)

        # Ground the prompt in exact scan-report matches, same as ask() —
        # previously ask_stream() skipped this and could stream fabricated
        # file names, line numbers, and vulnerabilities with no grounding.
        exact_ctx = ("" if intent is ChatIntent.GENERAL_SECURITY
                     else exact_match_context(question, self._scan_report))
        if exact_ctx:
            rag_result.merged_context = exact_ctx + "\n\n" + rag_result.merged_context

        messages   = self._builder.build(
            question=question,
            rag_result=rag_result,
            history=self._memory.get_history(),
            repo_summary=self._memory.context.repo_summary,
        )

        self._memory.add_user_message(question)
        accumulated = ""

        try:
            for token in self._llm.chat_stream(messages):
                accumulated += token
                yield token
        except LLMError as exc:
            error_msg = (
                f"\n\n⚠️ LLM error: {exc}\n"
                f"Check NVIDIA_API_KEY, model '{self._cfg.chat_model}', and connectivity."
            )
            accumulated += error_msg
            yield error_msg

        # Append citations after stream ends
        latency = (time.time() - t0) * 1000
        grounded = _NOT_FOUND_MARKER not in accumulated and (bool(rag_result.chunks) or bool(exact_ctx))

        # Mechanical hallucination check (same as ask()): validate the fully
        # accumulated answer against the scan report and warn on unverified
        # file/line/rule references instead of letting them stream unchecked.
        if self._validator is not None:
            verdict = self._validator.validate(accumulated)
            if not verdict.ok:
                warning = verdict.warning_block()
                accumulated += warning
                yield warning
                grounded = False

        citation_block = self._citation_block(rag_result.citations, grounded)
        if citation_block:
            yield citation_block
            accumulated += citation_block

        self._memory.add_assistant_text(accumulated, rag_result.citations)

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------

    def clear_history(self) -> None:
        self._memory.clear()

    def get_retrieval_context(self, question: str, top_k: int = 5) -> RAGResult:
        """Expose raw retrieval result (used by Streamlit debug panel)."""
        return self._retriever.retrieve(
            RAGQuery(question=question, top_k=top_k)
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append_citations(answer: str, citations: list[str], grounded: bool) -> str:
        if not citations or not grounded:
            return answer
        block = "\n\n---\n**Sources:**\n" + "\n".join(f"- {c}" for c in citations)
        # Don't duplicate if the LLM already added a Sources section
        if "Sources:" in answer or "sources:" in answer.lower():
            return answer
        return answer + block

    @staticmethod
    def _citation_block(citations: list[str], grounded: bool) -> str:
        if not citations or not grounded:
            return ""
        return "\n\n---\n**Sources:**\n" + "\n".join(f"- {c}" for c in citations)

    def _log_eval(self, question: str, rag_result: RAGResult, response: AssistantResponse) -> None:
        """Append evaluation record to JSONL file."""
        record = {
            "question":         question,
            "retrieval_count":  len(rag_result.chunks),
            "grounded":         response.grounded,
            "intent":           response.intent,
            "latency_ms":       response.latency_ms,
            "top_sources":      response.citations[:3],
            "answer_length":    len(response.answer),
        }
        try:
            with open(self._cfg.eval_log_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass
