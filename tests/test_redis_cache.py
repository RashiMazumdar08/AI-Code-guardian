"""Tests for Redis caching of UST and embeddings."""
from pathlib import Path
from unittest.mock import patch

import fakeredis
import pytest

from guardian.cache.redis_manager import RedisManager
from guardian.ust.builder import USTBuilder
from guardian.ust.models import USTFile, UST, USTNodeType


@pytest.fixture
def mock_redis():
    """Mock RedisManager.client with fakeredis."""
    fake_client = fakeredis.FakeRedis(decode_responses=True)
    with patch("guardian.cache.redis_manager.redis.Redis", return_value=fake_client):
        yield fake_client


def test_ust_builder_cache_hit_skips_parsing(mock_redis, tmp_path):
    # Setup dummy repo
    repo_dir = tmp_path / "dummy_repo"
    repo_dir.mkdir()
    source_file = repo_dir / "test.py"
    source_file.write_text("def hello(): pass")

    builder = USTBuilder()

    # Run once to cache.
    #
    # NOTE: build_repository() caches per-file by content hash and, for a
    # single cache-miss file, parses it inline via self.build_source(...)
    # (not self.build_file() -- that's only used by callers that build a
    # single file outside of a repository scan; when build_repository()
    # does parallelize misses across a process pool, each worker builds
    # its own separate USTBuilder instance, so patching this instance's
    # method wouldn't observe those calls either). Assert against
    # build_source, the method actually invoked on the cache-miss path.
    with patch.object(builder, "build_source", wraps=builder.build_source) as mock_build:
        ust1 = builder.build_repository(repo_dir, [source_file])
        mock_build.assert_called_once()
        assert len(ust1.files) == 1

    # Run again, should hit cache
    with patch.object(builder, "build_source") as mock_build2:
        ust2 = builder.build_repository(repo_dir, [source_file])
        mock_build2.assert_not_called()  # Parsing skipped!
        assert len(ust2.files) == 1
        
        # Verify node hydration
        file_ast = list(ust2.files.values())[0]
        nodes = file_ast.nodes
        assert any(n.type == USTNodeType.FUNCTION for n in nodes)
