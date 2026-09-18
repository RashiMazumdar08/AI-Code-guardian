"""
Redis Checkpointer for LangGraph Conversational Memory
======================================================
Handles state persistence across workflow turns using langgraph-checkpoint-redis.
Falls back to MemorySaver if Redis is unavailable.
"""

import logging
from typing import Any

from guardian.cache.redis_manager import RedisManager

logger = logging.getLogger(__name__)


def get_checkpointer() -> Any:
    """
    Returns a configured langgraph checkpointer.
    Prefers RedisSaver, falls back to MemorySaver on connection error.
    """
    # 1. First ensure we can connect to Redis
    redis_mgr = RedisManager()
    
    if redis_mgr.enabled and redis_mgr._pool:
        try:
            from langgraph.checkpoint.redis import RedisSaver
            import redis
            conn = redis.Redis(connection_pool=redis_mgr._pool)
            return RedisSaver(conn)
        except ImportError:
            logger.warning("langgraph-checkpoint-redis is not installed. Falling back to MemorySaver.")
        except Exception as exc:
            logger.warning(f"Failed to initialize RedisSaver: {exc}. Falling back to MemorySaver.")

    # 2. Fallback to in-memory checkpointer
    logger.info("Using in-memory MemorySaver for state checkpointing.")
    from langgraph.checkpoint.memory import MemorySaver
    return MemorySaver()
