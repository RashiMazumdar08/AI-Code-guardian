"""
AI Code Guardian — AI Assistant Configuration
===============================================
Single source of truth for every tunable value in the assistant.

Model names, embedding dimensions, chunking parameters, and
retrieval settings live here. Nothing is hardcoded in other modules.

Usage
-----
    from guardian.ai.config import AssistantConfig
    cfg = AssistantConfig()              # sensible defaults
    cfg = AssistantConfig(embed_device="cuda")   # override one field
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ASSISTANT_DIR = _PROJECT_ROOT / "ai_assistant"
_DEFAULT_INDEX_DIR = _PROJECT_ROOT / ".acg_index"


# ---------------------------------------------------------------------------
# Main config dataclass
# ---------------------------------------------------------------------------
@dataclass
class AssistantConfig:
    # ── LLM provider (chat / generation) ────────────────────────────────────
    # Inference is delegated entirely to `guardian.llm` (NVIDIA Nemotron).
    # Provider credentials live in LLMConfig / environment, never here.
    llm_provider: str = field(
        default_factory=lambda: os.getenv("ACG_LLM_PROVIDER", "nemotron")
    )
    # Deprecated alias kept so existing callers/tests that read
    # `cfg.chat_model` keep working; the real model name is NVIDIA_MODEL.
    chat_model: str = field(
        default_factory=lambda: os.getenv("NVIDIA_MODEL",
                                          "nvidia/nemotron-3-ultra-550b-a55b")
    )
    llm_stream: bool = True            # stream tokens to Streamlit

    # ── Embeddings (LOCAL — never sent to a remote API) ──────────────────────
    # all-MiniLM-L6-v2 = 384-dim. Changing this REQUIRES a FAISS rebuild.
    embed_model: str = field(
        default_factory=lambda: os.getenv("ACG_EMBED_MODEL",
                                          "sentence-transformers/all-MiniLM-L6-v2")
    )
    embed_device: str = field(
        default_factory=lambda: os.getenv("ACG_EMBED_DEVICE", "cpu")
    )
    embed_batch_size: int = 32
    # Hard ceiling on the ONE-TIME lazy download/load of the embedding
    # model (and CodeBERT below) from Hugging Face on first use. Without
    # this, a blocked/slow network to huggingface.co hangs the chat
    # request indefinitely instead of failing fast and letting the
    # chatbot answer without repository retrieval.
    model_load_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("ACG_MODEL_LOAD_TIMEOUT", "20"))
    )

    # ── CodeBERT ────────────────────────────────────────────────────────────
    codebert_model: str = "microsoft/codebert-base"
    codebert_device: str = field(
        default_factory=lambda: os.getenv("ACG_CODEBERT_DEVICE", "cpu")
    )
    codebert_batch_size: int = 8
    codebert_max_tokens: int = 512

    # ── Embeddings ───────────────────────────────────────────────────────────
    # all-MiniLM-L6-v2 = 384 dims; MUST match the loaded embed_model
    embed_dim: int = field(
        default_factory=lambda: int(os.getenv("ACG_EMBED_DIM", "384"))
    )
    codebert_dim: int = 768            # CodeBERT CLS token is always 768

    # ── FAISS Index ──────────────────────────────────────────────────────────
    index_dir: Path = field(default_factory=lambda: _DEFAULT_INDEX_DIR)
    # Separate index files for text docs and code
    doc_index_file: str = "doc_index.faiss"
    doc_meta_file: str = "doc_meta.pkl"
    code_index_file: str = "code_index.faiss"
    code_meta_file: str = "code_meta.pkl"
    faiss_nlist: int = 64             # IVF clusters (used when > 1000 vectors)
    faiss_nprobe: int = 8             # probed clusters at query time

    # ── Chunking ─────────────────────────────────────────────────────────────
    chunk_size: int = 512             # characters per chunk
    chunk_overlap: int = 64           # character overlap between chunks
    code_chunk_lines: int = 40        # lines per code chunk
    code_chunk_overlap_lines: int = 5

    # ── Retrieval ────────────────────────────────────────────────────────────
    retrieval_top_k: int = 8          # total chunks to retrieve
    code_top_k: int = 4               # code-specific retrieval
    doc_top_k: int = 4                # document-specific retrieval
    retrieval_score_threshold: float = 1.25  # MAX L2 distance; chunks scoring worse are dropped.
                                              # 0 disables filtering (NOT recommended: unfiltered
                                              # retrieval was the primary hallucination cause).
    temperature: float = 0.1                  # factual answers, not creative writing
    rerank: bool = False              # set True when cross-encoder is available

    # ── Prompt / Context window ───────────────────────────────────────────────
    max_context_chars: int = 12_000   # hard cap on total context sent to LLM
    max_history_turns: int = 6        # conversation turns kept in memory
    system_prompt_path: Path = field(
        default_factory=lambda: _ASSISTANT_DIR / "prompts" / "system.txt"
    )

    # ── Supported file extensions ─────────────────────────────────────────────
    code_extensions: tuple[str, ...] = (
        ".java", ".py", ".js", ".ts", ".go", ".rs", ".kt",
        ".cpp", ".c", ".cs", ".php", ".rb", ".scala",
    )
    doc_extensions: tuple[str, ...] = (
        ".md", ".txt", ".rst",
        ".json", ".yaml", ".yml", ".xml", ".csv",
        ".sql", ".sh", ".dockerfile", ".tf",
    )
    # These need specialized parsers (loaded lazily to avoid import errors)
    rich_extensions: tuple[str, ...] = (".pdf", ".docx")
    special_filenames: tuple[str, ...] = (
        "Dockerfile", "Jenkinsfile", "Makefile",
        ".github",                         # directory — walk contents
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = field(
        default_factory=lambda: os.getenv("ACG_LOG_LEVEL", "INFO")
    )
    log_file: Path | None = None      # None = stderr only

    # ── Evaluation ───────────────────────────────────────────────────────────
    eval_enabled: bool = False
    eval_log_file: Path = field(
        default_factory=lambda: _DEFAULT_INDEX_DIR / "eval_log.jsonl"
    )

    def __post_init__(self):
        # Ensure index dir exists
        self.index_dir = Path(self.index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)

    @property
    def doc_index_path(self) -> Path:
        return self.index_dir / self.doc_index_file

    @property
    def doc_meta_path(self) -> Path:
        return self.index_dir / self.doc_meta_file

    @property
    def code_index_path(self) -> Path:
        return self.index_dir / self.code_index_file

    @property
    def code_meta_path(self) -> Path:
        return self.index_dir / self.code_meta_file

    @property
    def all_indexable_extensions(self) -> tuple[str, ...]:
        return self.code_extensions + self.doc_extensions + self.rich_extensions


# ---------------------------------------------------------------------------
# Module-level default instance (import and override if needed)
# ---------------------------------------------------------------------------
default_config = AssistantConfig()
