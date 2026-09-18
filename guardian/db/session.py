"""
Database Session Management for AI Code Guardian
================================================
Handles async engine creation, connection health checks, and fallback logic.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

log = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = "postgresql+asyncpg://guardian:guardian_pass@localhost:5432/guardian_db"

_engine: Optional[AsyncEngine] = None
_is_postgres_healthy: Optional[bool] = None


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        db_url = get_database_url()
        _engine = create_async_engine(
            db_url,
            echo=False,
            future=True,
            connect_args={"timeout": 2} if "asyncpg" in db_url else {},
        )
    return _engine


async def is_postgres_available() -> bool:
    """Check if the configured PostgreSQL database is online and reachable.

    Falls back to False gracefully if offline, missing drivers, or unreachable.
    """
    global _is_postgres_healthy
    db_url = get_database_url()
    if not db_url.startswith("postgresql"):
        _is_postgres_healthy = False
        return False

    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")
        _is_postgres_healthy = True
        return True
    except Exception as e:
        log.debug(f"PostgreSQL connection check failed: {e}")
        _is_postgres_healthy = False
        return False


async def init_db() -> bool:
    """Initialize database tables if PostgreSQL is available."""
    if await is_postgres_available():
        try:
            engine = get_engine()
            async with engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)
            return True
        except Exception as e:
            log.warning(f"Database initialization failed: {e}")
            return False
    return False


def get_async_session() -> sessionmaker:
    engine = get_engine()
    return sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
