"""
AI Layer — Local Embedding Provider
===================================
Local sentence-transformers embeddings for repository retrieval.

Why this exists
---------------
Nemotron handles chat inference through the hosted NVIDIA endpoint.
Embeddings stay local because:

  * FAISS indexes are dimension-locked. Mixing providers mid-index
    silently corrupts similarity search.
  * Embedding every chunk of a large repository through a remote API
    means transmitting the entire codebase, which defeats the
    context-compression rule (spec §5) and worsens the exfiltration
    exposure that migrating to a cloud LLM already introduces.
  * Embeddings are cheap locally and need no GPU at this model size.

Default model: `sentence-transformers/all-MiniLM-L6-v2` (384-dim, ~80 MB,
CPU-friendly). CodeBERT continues to handle source-code chunks exactly
as before — this provider serves text/document chunks and acts as the
fallback when CodeBERT is unavailable.

IMPORTANT — index rebuild required when changing embedding dimensions.
`AssistantConfig.embed_dim` defaults to 384; set ACG_EMBED_MODEL and
ACG_EMBED_DIM together if you swap models.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

DEFAULT_EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_EMBED_DIM = 384


class EmbeddingError(Exception):
    """Raised when the embedding backend cannot produce vectors."""


class LocalEmbedder:
    """Sentence-transformers embedding provider (CPU by default).

    The model is loaded lazily on first use so that importing this module
    — which the whole AI package does — never pays a multi-second model
    load or fails in environments where the dependency is absent.
    """

    def __init__(self, model_name: str = DEFAULT_EMBED_MODEL,
                 device: str = "cpu", dim: int = DEFAULT_EMBED_DIM,
                 batch_size: int = 32, load_timeout: int = 20):
        self.model_name = model_name
        self.device = device
        self.dim = dim
        self.batch_size = batch_size
        self.load_timeout = load_timeout
        self._model = None
        self._load_failed = False

    # ------------------------------------------------------------------
    @property
    def model(self):
        if self._model is None and not self._load_failed:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError:
                self._load_failed = True
                log.error("sentence-transformers is not installed. "
                          "Install it: pip install sentence-transformers")
                return self._model

            # Load on a background DAEMON thread rather than via
            # ThreadPoolExecutor: a pool's context manager (and even a bare
            # shutdown()) blocks on exit until the worker finishes, which
            # would defeat the timeout if the download is genuinely hung —
            # we'd still wait for it, just with extra steps. A daemon
            # thread lets us give up after `load_timeout` and move on; if
            # the download eventually finishes in the background it is
            # simply discarded (self._load_failed is already latched).
            import threading
            box: dict = {}

            def _do_load():
                try:
                    box["model"] = SentenceTransformer(self.model_name, device=self.device)
                except Exception as exc:  # noqa: BLE001
                    box["error"] = exc

            log.info("loading local embedding model %s on %s (timeout=%ss)",
                     self.model_name, self.device, self.load_timeout)
            worker = threading.Thread(target=_do_load, daemon=True)
            worker.start()
            worker.join(timeout=self.load_timeout)

            if worker.is_alive():
                self._load_failed = True
                log.error(
                    "Timed out after %ss loading '%s' — this is a one-time "
                    "download from huggingface.co on first use. If your "
                    "network can't reach Hugging Face, retrieval will be "
                    "skipped for this session; the chatbot will still "
                    "answer general questions without repository context. "
                    "Increase ACG_MODEL_LOAD_TIMEOUT if you're on a slow "
                    "connection and it just needs more time.",
                    self.load_timeout, self.model_name)
                return None

            if "error" in box:
                self._load_failed = True
                log.error("failed to load embedding model %s: %s", self.model_name, box["error"])
                return None

            self._model = box.get("model")
            if self._model is not None:
                actual = self._model.get_sentence_embedding_dimension()
                if actual != self.dim:
                    log.warning(
                        "embed_dim mismatch: configured %d, model produces %d. "
                        "Using %d — rebuild the FAISS index if it was built at "
                        "the old dimension.", self.dim, actual, actual)
                    self.dim = actual
        return self._model

    @property
    def is_available(self) -> bool:
        return self.model is not None

    # ------------------------------------------------------------------
    def embed(self, text: str) -> list[float]:
        """Embed one string. Raises EmbeddingError if the backend is down —
        callers that prefer degradation catch it (see EmbeddingRouter)."""
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: list[str], show_progress: bool = False) -> list[list[float]]:
        if not texts:
            return []
        model = self.model
        if model is None:
            raise EmbeddingError(
                "Local embedding model unavailable. Install the dependency:\n"
                "    pip install sentence-transformers")
        try:
            vectors = model.encode(
                texts, batch_size=self.batch_size,
                show_progress_bar=show_progress,
                convert_to_numpy=True, normalize_embeddings=False)
        except Exception as exc:  # noqa: BLE001
            raise EmbeddingError(f"Local embedding failed: {exc}") from exc
        return [np.asarray(v, dtype=np.float32).tolist() for v in vectors]

    def is_healthy(self) -> bool:
        return self.is_available
