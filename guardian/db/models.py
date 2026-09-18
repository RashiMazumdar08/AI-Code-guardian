"""
Database Models for AI Code Guardian
====================================
SQLModel schemas for Scans, Findings, Evidence Items, and Knowledge Embeddings.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

try:
    from pgvector.sqlalchemy import Vector
    HAS_PGVECTOR = True
except ImportError:
    HAS_PGVECTOR = False


class ScanTable(SQLModel, table=True):
    """Represents a code repository scan execution."""
    __tablename__ = "scan_records"
    __table_args__ = {'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    repo_path: str
    branch: Optional[str] = None
    scan_mode: Optional[str] = None
    status: str = "completed"
    summary_json: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingTable(SQLModel, table=True):
    """Represents a security finding or vulnerability detected during a scan."""
    __tablename__ = "finding_records"
    __table_args__ = {'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_id: Optional[uuid.UUID] = Field(default=None, foreign_key="scan_records.id")
    cwe_id: Optional[str] = None
    title: str
    severity: str
    is_exploitable: bool = False
    exploitability_score: float = 0.0
    status: str = "open"


class EvidenceItemTable(SQLModel, table=True):
    """Represents deterministic evidence grounded in source code."""
    __tablename__ = "evidence_item_records"
    __table_args__ = {'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    finding_id: Optional[uuid.UUID] = Field(default=None, foreign_key="finding_records.id")
    file_path: str
    line_start: int = 0
    line_end: int = 0
    ast_node_type: Optional[str] = None
    snippet: Optional[str] = None

    # Additional metadata fields for Evidence object integration
    evidence_key: Optional[str] = None  # e.g., "E1"
    evidence_type: Optional[str] = None
    source: Optional[str] = None
    symbol: Optional[str] = None
    operation: Optional[str] = None
    confidence: float = 1.0
    fingerprint: Optional[str] = None


class KnowledgeEmbeddingTable(SQLModel, table=True):
    """Represents vector embeddings for security knowledge/rules (RAG)."""
    __table_args__ = {'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    cwe_id: Optional[str] = None
    content: str
    if HAS_PGVECTOR:
        embedding: Optional[List[float]] = Field(
            default=None,
            sa_column=Column(Vector(384))
        )
    else:
        embedding: Optional[str] = None
