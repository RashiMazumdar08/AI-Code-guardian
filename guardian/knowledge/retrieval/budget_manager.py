"""
AI Code Guardian v3 — Context Budget Manager
=============================================
Manages token footprint budgeting, deduplication, and Evidence ID prioritization
for RAG retrieval context payloads prior to prompt injection.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set


class ContextBudgetManager:
    """Manages token limits, deduplication, and evidence prioritization for RAG context."""

    EVIDENCE_ID_PATTERN = re.compile(r'\b(?:E\d+|EV-\d+|[A-Z]{2,4}-\d+)\b', re.IGNORECASE)

    def __init__(
        self,
        max_tokens: int = 2000,
        max_chunks: int = 10,
        chars_per_token: int = 4
    ) -> None:
        self.max_tokens = max_tokens
        self.max_chunks = max_chunks
        self.chars_per_token = chars_per_token

    def _estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        return len(text) // self.chars_per_token + 1

    def _hash_content(self, content: str) -> str:
        cleaned = "".join(content.split()).lower()
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

    def _extract_evidence_ids(self, item: Dict[str, Any]) -> List[str]:
        ids: Set[str] = set()
        if item.get("evidence_id"):
            ids.add(str(item["evidence_id"]))
        if item.get("evidence_ids"):
            for eid in item["evidence_ids"]:
                ids.add(str(eid))
        text_to_search = f"{item.get('content', '')} {item.get('text', '')} {item.get('title', '')} {item.get('metadata', '')}"
        found = self.EVIDENCE_ID_PATTERN.findall(text_to_search)
        for f in found:
            ids.add(f.upper())
        return list(ids)

    def trim_and_format(
        self,
        items: List[Dict[str, Any]],
        active_evidence_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Deduplicates, prioritizes Evidence IDs, and truncates retrieved items to fit token budget.
        """
        if not items:
            return {
                "formatted_context": "No relevant context found.",
                "used_tokens": 0,
                "included_items": [],
                "dropped_items": [],
                "evidence_ids_included": []
            }

        active_set: Set[str] = set(eid.upper() for eid in (active_evidence_ids or []))

        # 1. Deduplicate by content hash
        seen_hashes: Set[str] = set()
        deduped_items: List[Dict[str, Any]] = []

        for item in items:
            content = str(item.get("content") or item.get("text") or item.get("snippet") or str(item))
            chash = self._hash_content(content)
            if chash in seen_hashes:
                continue
            seen_hashes.add(chash)
            
            extracted_ids = self._extract_evidence_ids(item)
            item_copy = dict(item)
            item_copy["_extracted_evidence_ids"] = extracted_ids
            item_copy["_content_str"] = content
            deduped_items.append(item_copy)

        # 2. Prioritize items: Evidence ID matches / active evidence -> highest priority
        def _priority_key(item: Dict[str, Any]) -> tuple:
            extracted = set(item["_extracted_evidence_ids"])
            matches_active = bool(extracted.intersection(active_set))
            has_evidence_id = len(extracted) > 0
            rrf_score = float(item.get("rrf_score") or item.get("score") or 0.0)
            return (1 if matches_active else 0, 1 if has_evidence_id else 0, rrf_score)

        sorted_items = sorted(deduped_items, key=_priority_key, reverse=True)

        # 3. Budget enforcement
        included: List[Dict[str, Any]] = []
        dropped: List[Dict[str, Any]] = []
        included_evidence_ids: Set[str] = set()
        current_tokens = 0

        for item in sorted_items:
            content_str = item["_content_str"]
            item_tokens = self._estimate_tokens(content_str)

            if len(included) >= self.max_chunks or (current_tokens + item_tokens > self.max_tokens and included):
                dropped.append(item)
                continue

            included.append(item)
            current_tokens += item_tokens
            included_evidence_ids.update(item["_extracted_evidence_ids"])

        # 4. Format payload string
        formatted_chunks = []
        for idx, item in enumerate(included, 1):
            title = item.get("title") or item.get("id") or item.get("name") or f"Item {idx}"
            source_type = item.get("source_type") or item.get("category") or "retrieved"
            ev_ids = item["_extracted_evidence_ids"]
            ev_str = f" [Evidence: {', '.join(ev_ids)}]" if ev_ids else ""
            formatted_chunks.append(f"### Chunk {idx}: [{source_type.upper()}] {title}{ev_str}\n{item['_content_str']}")

        formatted_context = "\n\n".join(formatted_chunks)

        return {
            "formatted_context": formatted_context,
            "used_tokens": current_tokens,
            "included_items": included,
            "dropped_items": dropped,
            "evidence_ids_included": list(included_evidence_ids)
        }
