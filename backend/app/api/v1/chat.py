"""
Chat & Reasoning API Endpoint
=============================
Provides interactive AI completions grounded in scan evidence via the
full RAG pipeline (retriever + prompt builder + exact-match scan-report
context + mechanical response validation), instead of a hand-rolled
prompt built ad hoc per request.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from guardian.ai.chatbot import AISecurityCopilot

router = APIRouter(prefix="/chat", tags=["chat"])
logger = logging.getLogger("guardian.api.chat")


class ChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message content")


class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    persona: str = Field("Developer", description="Persona: 'Executive', 'Developer', or 'Red Teamer'")
    temperature: float = Field(0.2, ge=0.0, le=1.0)
    report: Optional[dict] = Field(None, description="Active scan report object from client")


class ChatCompletionResponse(BaseModel):
    persona: str
    reply: str
    tools_used: List[str] = Field(default_factory=list)
    # GENERAL_SECURITY / REPOSITORY / MIXED / CONVERSATIONAL -- see
    # guardian/ai/intent_router.py. Surfaced so the UI can show why a
    # question wasn't (or was) grounded in scan-report specifics.
    intent: str = Field("MIXED", description="Chatbot intent classification for this question.")


class ChatStreamRequest(BaseModel):
    message: str
    thread_id: str


# ---------------------------------------------------------------------------
# Shared, lazily-built AISecurityCopilot (RAG pipeline: retriever, prompt
# builder, ResponseValidator, exact_match_context). Building it loads the
# local embedding model, so it is built once and reused across requests
# rather than per-request.
# ---------------------------------------------------------------------------
_copilot: Optional[AISecurityCopilot] = None
_copilot_lock = asyncio.Lock()
_last_synced_scan_id: Optional[str] = None


async def _get_copilot() -> AISecurityCopilot:
    global _copilot
    if _copilot is None:
        async with _copilot_lock:
            if _copilot is None:  # re-check inside the lock
                loop = asyncio.get_event_loop()
                _copilot = await loop.run_in_executor(None, AISecurityCopilot.create)
    return _copilot


def _sync_latest_scan(copilot: AISecurityCopilot, client_report: Optional[dict] = None) -> None:
    """Ground the RAG pipeline in the scan report (client-supplied or latest in store)."""
    global _last_synced_scan_id
    report = client_report
    if not report:
        try:
            from backend.app.api.v1.scans import _SCANS_STORE
            if _SCANS_STORE:
                scan_id, report = list(_SCANS_STORE.items())[-1]
        except ImportError:
            pass

    if not report:
        return

    scan_id = report.get("scan_id") or report.get("id") or "active_scan"
    if scan_id == _last_synced_scan_id and client_report is None:
        return

    repo_root = report.get("target") or (report.get("repository") or {}).get("root")
    try:
        copilot.clear_index()
        copilot.index_scan_report(report, repo_root=repo_root)
        _last_synced_scan_id = scan_id
    except Exception as exc:  # noqa: BLE001 — grounding must never break chat
        logger.warning("Failed to sync scan into copilot context: %s", exc)


from guardian.llm.rate_limit_handler import is_rate_limit_error, format_rate_limit_warning


@router.post("/completions", response_model=ChatCompletionResponse)
async def chat_completion(request: ChatCompletionRequest):
    try:
        user_query = (request.messages[-1].content if request.messages else "").strip()
        if not user_query:
            raise HTTPException(status_code=400, detail="No user message provided.")

        copilot = await _get_copilot()
        _sync_latest_scan(copilot, client_report=request.report)

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, copilot.ask, user_query)

        tools_used = ["retriever", "prompt_builder"]
        if response.grounded:
            tools_used.append("exact_match_context")
        tools_used.append("response_validator")

        return ChatCompletionResponse(
            persona=request.persona,
            reply=response.answer,
            tools_used=tools_used,
            intent=response.intent,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat completion failed: {str(e)}", exc_info=True)
        if is_rate_limit_error(e):
            user_query = (request.messages[-1].content if request.messages else "").strip()
            msg = format_rate_limit_warning(e, user_query=user_query, scan_report=request.report)
            return ChatCompletionResponse(
                persona=request.persona,
                reply=msg,
                tools_used=["rate_limit_handler"],
                intent="GENERAL_SECURITY",
            )
        raise HTTPException(status_code=500, detail=f"Chat completion error: {str(e)}")


@router.post("/stream")
async def chat_stream(request: ChatStreamRequest):
    """Streams the grounded RAG Copilot response (guardian.ai.rag_pipeline)
    over Server-Sent Events. Replaces the previous OrchestratorWorkflow-based
    stream, which returned unvalidated raw LLM tokens with no grounding."""

    async def event_generator():
        try:
            copilot = await _get_copilot()
            _sync_latest_scan(copilot)
        except Exception as e:  # noqa: BLE001 — surface as an SSE error event
            logger.error(f"Copilot initialization failed: {str(e)}", exc_info=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"
            return

        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()
        _SENTINEL = object()

        def _produce() -> None:
            try:
                for token in copilot.ask_stream(request.message):
                    loop.call_soon_threadsafe(queue.put_nowait, token)
            except Exception as e:  # noqa: BLE001
                loop.call_soon_threadsafe(queue.put_nowait, {"__error__": str(e)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, _SENTINEL)

        threading.Thread(target=_produce, daemon=True).start()

        while True:
            item = await queue.get()
            if item is _SENTINEL:
                break
            if isinstance(item, dict) and "__error__" in item:
                yield f"data: {json.dumps({'error': item['__error__']})}\n\n"
                break
            yield f"data: {json.dumps({'content': item})}\n\n"

        yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
