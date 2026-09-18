"""
AI Code Guardian — CodeBERT Embeddings
========================================
microsoft/codebert-base is used EXCLUSIVELY for semantic code embeddings.
It never generates text — that is the local embedder's job.

CodeBERT excels at understanding:
  - Security-sensitive code patterns (auth, crypto, injection sinks)
  - Functionally similar implementations across different files
  - Authorization / authentication flows
  - Business logic encoded in method names and structure

Architecture
------------
    CodeBERT tokenizer → [CLS] token embedding (768-dim) → FAISS index

The CLS embedding captures the semantic meaning of the whole code snippet.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from guardian.ai.config import AssistantConfig

logger = logging.getLogger(__name__)

# Lazy module-level singletons — loaded once on first call
_tokenizer = None
_model = None
_config_ref: Optional[AssistantConfig] = None


_load_failed = False


def _load_model(config: AssistantConfig):
    """Load CodeBERT tokenizer and model (once per process).

    Wrapped in a background-thread timeout: microsoft/codebert-base is a
    ~500MB one-time download from Hugging Face, and without a timeout a
    blocked/slow network hangs the whole request indefinitely instead of
    failing fast (CodeBERT is optional — the local embedder covers code
    as a fallback, per chatbot.py).
    """
    global _tokenizer, _model, _config_ref, _load_failed
    if _tokenizer is not None or _load_failed:
        return
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as e:
        raise ImportError(
            "torch and transformers are required for CodeBERT. "
            "Install with: pip install torch transformers"
        ) from e

    # Load on a background DAEMON thread, not a ThreadPoolExecutor: a
    # pool's context manager blocks on exit until the worker finishes,
    # which would defeat the timeout if the download is genuinely hung.
    # A daemon thread lets us give up after `timeout` and move on.
    import threading
    timeout = getattr(config, "model_load_timeout_seconds", 20)
    box: dict = {}

    def _do_load():
        try:
            tok = AutoTokenizer.from_pretrained(config.codebert_model)
            mdl = AutoModel.from_pretrained(config.codebert_model)
            mdl.eval()
            mdl.to(config.codebert_device)
            box["result"] = (tok, mdl)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    logger.info("Loading CodeBERT: %s on %s (timeout=%ss)",
               config.codebert_model, config.codebert_device, timeout)
    worker = threading.Thread(target=_do_load, daemon=True)
    worker.start()
    worker.join(timeout=timeout)

    if worker.is_alive():
        _load_failed = True
        logger.error(
            "CodeBERT load timed out after %ss (likely no/slow network "
            "access to Hugging Face). Falling back to the local embedder "
            "for code — see guardian/ai/chatbot.py._try_load_codebert.",
            timeout)
        raise TimeoutError(f"CodeBERT load exceeded {timeout}s timeout")

    if "error" in box:
        _load_failed = True
        raise box["error"]

    _tokenizer, _model = box["result"]
    _config_ref = config
    logger.info("CodeBERT loaded successfully")


class CodeBERTEmbedder:
    """
    Produces 768-dimensional semantic embeddings for source code snippets.

    Usage
    -----
        embedder = CodeBERTEmbedder(config)
        vec = embedder.embed("public void authenticate(User user) { ... }")
        batch = embedder.embed_batch(["snippet1", "snippet2"])
    """

    def __init__(self, config: AssistantConfig):
        self._cfg = config
        _load_model(config)

    def embed(self, code: str) -> np.ndarray:
        """
        Embed a single code snippet. Returns a (768,) float32 ndarray.
        The [CLS] token representation is used as the sentence-level embedding.
        """
        import torch
        if not code.strip():
            return np.zeros(self._cfg.codebert_dim, dtype=np.float32)
        try:
            inputs = _tokenizer(
                code,
                return_tensors="pt",
                max_length=self._cfg.codebert_max_tokens,
                truncation=True,
                padding=True,
            )
            inputs = {k: v.to(self._cfg.codebert_device) for k, v in inputs.items()}
            with torch.no_grad():
                outputs = _model(**inputs)
            # CLS token = first token of last hidden state
            cls_vec = outputs.last_hidden_state[:, 0, :].squeeze().cpu().numpy()
            # L2-normalise for cosine similarity via dot product
            norm = np.linalg.norm(cls_vec)
            if norm > 0:
                cls_vec = cls_vec / norm
            return cls_vec.astype(np.float32)
        except Exception as exc:
            logger.warning("CodeBERT embed failed for snippet: %s", exc)
            return np.zeros(self._cfg.codebert_dim, dtype=np.float32)

    def embed_batch(self, snippets: list[str]) -> np.ndarray:
        """
        Embed multiple code snippets in batches.
        Returns shape (N, 768) float32 ndarray.
        """
        import torch
        if not snippets:
            return np.zeros((0, self._cfg.codebert_dim), dtype=np.float32)

        all_vecs = []
        batch_size = self._cfg.codebert_batch_size

        for i in range(0, len(snippets), batch_size):
            batch = snippets[i : i + batch_size]
            non_empty = [s if s.strip() else " " for s in batch]
            try:
                inputs = _tokenizer(
                    non_empty,
                    return_tensors="pt",
                    max_length=self._cfg.codebert_max_tokens,
                    truncation=True,
                    padding=True,
                )
                inputs = {k: v.to(self._cfg.codebert_device) for k, v in inputs.items()}
                with torch.no_grad():
                    outputs = _model(**inputs)
                cls_vecs = outputs.last_hidden_state[:, 0, :].cpu().numpy()
                # L2-normalise each row
                norms = np.linalg.norm(cls_vecs, axis=1, keepdims=True)
                norms = np.where(norms == 0, 1.0, norms)
                cls_vecs = (cls_vecs / norms).astype(np.float32)
                all_vecs.append(cls_vecs)
                if (i // batch_size + 1) % 10 == 0:
                    logger.debug(
                        "CodeBERT embedded %d/%d snippets",
                        min(i + batch_size, len(snippets)),
                        len(snippets),
                    )
            except Exception as exc:
                logger.warning("CodeBERT batch embed error at index %d: %s", i, exc)
                all_vecs.append(
                    np.zeros((len(batch), self._cfg.codebert_dim), dtype=np.float32)
                )

        return np.vstack(all_vecs)

    def similarity(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """Cosine similarity between two normalised embeddings (0 to 1)."""
        return float(np.dot(vec_a, vec_b))

    def most_similar(
        self,
        query_vec: np.ndarray,
        candidate_vecs: np.ndarray,
        top_k: int = 5,
    ) -> list[tuple[int, float]]:
        """
        Return top-k (index, similarity) pairs from candidate_vecs.
        Both query_vec and candidate_vecs should be L2-normalised.
        """
        scores = candidate_vecs @ query_vec        # (N,)
        top_indices = np.argsort(scores)[::-1][:top_k]
        return [(int(idx), float(scores[idx])) for idx in top_indices]
