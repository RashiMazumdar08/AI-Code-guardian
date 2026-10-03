"""
Code Semantic Indexing & Representation Module
================================================
Derives deterministic function/class/control-flow code chunk representations
from AST profiles and builds embedding-backed index for semantic search.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

log = logging.getLogger(__name__)

_INDEX_CACHE: Dict[str, Tuple[float, "CodeSemanticIndex"]] = {}


@dataclass
class CodeChunkRepresentation:
    chunk_id: str
    file: str
    function: str
    line: int
    chunk_type: str  # "FUNCTION", "CLASS", "CONTROL_FLOW", "DATA_FLOW"
    inputs: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    security_business_behavior: str = ""
    actions: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    snippet: str = ""
    summary_text: str = ""
    vector: Optional[np.ndarray] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "chunk_type": self.chunk_type,
            "inputs": self.inputs,
            "operations": self.operations,
            "security_business_behavior": self.security_business_behavior,
            "actions": self.actions,
            "controls": self.controls,
            "snippet": self.snippet[:400],
            "summary_text": self.summary_text,
        }


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]{3,}", text.lower()))


_LOCAL_EMBEDDER = None


def _get_local_embedder():
    global _LOCAL_EMBEDDER
    if _LOCAL_EMBEDDER is None:
        try:
            from guardian.ai.local_embedder import LocalEmbedder
            _LOCAL_EMBEDDER = LocalEmbedder()
        except Exception:
            _LOCAL_EMBEDDER = False
    return _LOCAL_EMBEDDER if _LOCAL_EMBEDDER is not False else None


class CodeSemanticIndex:
    """Indexes workspace code chunks into semantic representations and vector embeddings."""

    def __init__(self, workspace_dir: Optional[Path] = None):
        self.workspace_dir = (workspace_dir or Path.cwd()).resolve()
        self.chunks: list[CodeChunkRepresentation] = []
        self._vectors: Optional[np.ndarray] = None
        self._build_index()

    @classmethod
    def get_or_create(cls, workspace_dir: Optional[Path] = None) -> "CodeSemanticIndex":
        ws_path = (workspace_dir or Path.cwd()).resolve()
        ws_key = str(ws_path)
        try:
            py_files = list(ws_path.rglob("*.py")) if ws_path.exists() else []
            mtime = sum(p.stat().st_mtime for p in py_files) if py_files else 0.0
            cache_key = f"{ws_key}:{len(py_files)}"
        except Exception:
            mtime = 0.0
            cache_key = ws_key

        if cache_key in _INDEX_CACHE:
            cached_mtime, cached_index = _INDEX_CACHE[cache_key]
            if cached_mtime == mtime:
                return cached_index

        index = cls(workspace_dir=ws_path)
        _INDEX_CACHE[cache_key] = (mtime, index)
        return index

    def _build_index(self):
        from guardian.intent.matcher.rule_matcher import RuleMatcher

        ws_profiles = RuleMatcher._profiles_from_workspace(self.workspace_dir)
        self.chunks = []

        chunk_idx = 1
        for p in ws_profiles:
            fn_name = p.function_name
            file_name = p.file
            line_no = p.line

            inputs = getattr(p, "args", []) or []
            actions = getattr(p, "actions", []) or []
            controls = getattr(p, "controls", []) or []

            operations = []
            if hasattr(p, "if_statements"):
                for if_s in getattr(p, "if_statements", []) or []:
                    cond = if_s.get("condition", "")
                    if cond:
                        operations.append(f"guard_check: {cond}")
            if hasattr(p, "calls"):
                for call in getattr(p, "calls", []) or []:
                    c_name = call[0] if isinstance(call, (tuple, list)) else str(call)
                    operations.append(f"call: {c_name}")
            if hasattr(p, "assignments"):
                for assign in getattr(p, "assignments", []) or []:
                    if isinstance(assign, (tuple, list)) and len(assign) >= 2:
                        operations.append(f"assign: {assign[0]} = {assign[1]}")

            behavior = ""
            if actions and controls:
                behavior = f"action '{', '.join(actions[:3])}' protected by control '{', '.join(controls[:3])}'"
            elif actions:
                behavior = f"executes action '{', '.join(actions[:3])}'"
            elif controls:
                behavior = f"applies control '{', '.join(controls[:3])}'"
            else:
                behavior = "general execution logic"

            summary_parts = [
                f"Function: {fn_name}",
                f"File: {file_name}",
                f"Inputs: {', '.join(inputs) if inputs else 'none'}",
                f"Operations: {'; '.join(operations[:5]) if operations else 'standard execution'}",
                f"Security/business relevant behavior: {behavior}",
                f"Code snippet:\n{p.code_snippet[:300]}",
            ]
            summary_text = "\n".join(summary_parts)

            chunk = CodeChunkRepresentation(
                chunk_id=f"S{chunk_idx:03d}",
                file=file_name,
                function=fn_name,
                line=line_no,
                chunk_type="FUNCTION",
                inputs=inputs,
                operations=operations,
                security_business_behavior=behavior,
                actions=actions,
                controls=controls,
                snippet=p.code_snippet[:500],
                summary_text=summary_text,
            )
            self.chunks.append(chunk)
            chunk_idx += 1

        self._generate_embeddings()

    def _generate_embeddings(self):
        if not self.chunks:
            self._vectors = np.zeros((0, 384), dtype=np.float32)
            return

        try:
            embedder = _get_local_embedder()
            if embedder and embedder.is_available:
                texts = [c.summary_text for c in self.chunks]
                vec_list = embedder.embed_batch(texts)
                raw_vecs = np.array(vec_list, dtype=np.float32)
                norms = np.linalg.norm(raw_vecs, axis=1, keepdims=True)
                norms[norms == 0] = 1.0
                self._vectors = raw_vecs / norms
                for i, c in enumerate(self.chunks):
                    c.vector = self._vectors[i]
                return
        except Exception as exc:
            log.debug("LocalEmbedder unavailable for semantic index (%s); using TF-IDF fallback vectorizer", exc)

        # Robust local TF-IDF / N-gram cosine embedding fallback
        all_vocab = sorted({w for c in self.chunks for w in _tokenize(c.summary_text)})
        if not all_vocab:
            self._vectors = np.zeros((len(self.chunks), 1), dtype=np.float32)
            return

        vocab_map = {w: i for i, w in enumerate(all_vocab)}
        matrix = np.zeros((len(self.chunks), len(all_vocab)), dtype=np.float32)

        for i, c in enumerate(self.chunks):
            tokens = _tokenize(c.summary_text)
            for t in tokens:
                if t in vocab_map:
                    matrix[i, vocab_map[t]] += 1.0

        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self._vectors = matrix / norms
        for i, c in enumerate(self.chunks):
            c.vector = self._vectors[i]
