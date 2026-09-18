"""
AI Code Guardian v3 — Embedding Base Interface
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List


class BaseEmbedder(ABC):
    """Abstract interface for text and code embedding models."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Embeds a single string into a vector representation."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embeds multiple strings."""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Returns the embedding vector dimension."""
        pass
