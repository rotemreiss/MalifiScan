"""Unit tests for PackageCache."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.core.cache.package_cache import PackageCache
from src.core.entities import MaliciousPackage


@pytest.fixture
def sample_package():
    """Create a sample malicious package for testing."""
    return MaliciousPackage(
        name="test-package",
        version="1.0.0",
        ecosystem="npm",
        package_url="pkg:npm/test-package@1.0.0",
        advisory_id="TEST-001",
        summary="Test package for cache testing",
        details="Detailed description of the test package",
        aliases=["CVE-2024-TEST"],
        affected_versions=["1.0.0", "1.1.0"],
        database_specific={"severity": "HIGH"},
        published_at=datetime.now(timezone.utc),
        modified_at=datetime.now(timezone.utc),
    )


class TestPackageCacheWithoutRedis:
    """Test PackageCache when Redis is not available (no-cache mode)."""

    def test_init_without_redis(self):
        """Test initialization when Redis URL is not provided."""
        cache = PackageCache()

        assert cache._redis is None
        assert cache._use_cache is False

    def test_get_returns_none_when_no_cache(self, sample_package):
        """Test that get() returns None when cache is disabled."""
        cache = PackageCache()

        result = cache.get("TEST-001")
        assert result is None

    def test_put_does_nothing_when_no_cache(self, sample_package):
        """Test that put() does nothing when cache is disabled."""
        cache = PackageCache()

        # Should not raise an error
        cache.put("TEST-001", sample_package)

        # Should still return None when trying to get
        result = cache.get("TEST-001")
        assert result is None

    def test_has_returns_false_when_no_cache(self):
        """Test that has() returns False when cache is disabled."""
        cache = PackageCache()

        assert cache.has("TEST-001") is False

    def test_size_returns_zero_when_no_cache(self):
        """Test that size() returns 0 when cache is disabled."""
        cache = PackageCache()

        assert cache.size() == 0

    def test_purge_returns_zero_when_no_cache(self):
        """Test that purge() returns 0 when cache is disabled."""
        cache = PackageCache()

        count = cache.purge()
        assert count == 0

    def test_get_stats_when_no_cache(self):
        """Test that get_stats() returns no-cache information."""
        cache = PackageCache()

        stats = cache.get_stats()
        assert stats["total_packages"] == 0
        assert stats["backend"] == "none"
        assert stats["cache_enabled"] is False


class TestPackageCacheWithRedis:
    """Test PackageCache with Redis connection."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = MagicMock()
        mock.ping.return_value = True
        mock.get.return_value = None
        mock.set.return_value = True
        mock.exists.return_value = 0
        mock.delete.return_value = 0
        mock.scan_iter.return_value = iter([])
        return mock

    def test_init_with_redis_success(self, mock_redis):
        """Test successful initialization with Redis."""
        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")

            assert cache._redis is not None
            assert cache._use_cache is True
            mock_redis.ping.assert_called_once()

    def test_init_with_redis_connection_failure(self):
        """Test initialization when Redis connection fails."""
        with patch("redis.from_url", side_effect=ConnectionError("Connection refused")):
            cache = PackageCache(redis_url="redis://localhost:6379/0")

            assert cache._redis is None
            assert cache._use_cache is False

    def test_init_with_redis_import_error(self):
        """Test initialization when redis package is not installed."""
        with patch(
            "builtins.__import__", side_effect=ImportError("No module named 'redis'")
        ):
            cache = PackageCache(redis_url="redis://localhost:6379/0")

            assert cache._redis is None
            assert cache._use_cache is False

    def test_get_from_redis_cache_hit(self, mock_redis, sample_package):
        """Test successful retrieval from Redis cache."""
        package_json = json.dumps(sample_package.to_dict())
        mock_redis.get.return_value = package_json

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.get("TEST-001")

            assert result is not None
            assert result.name == sample_package.name
            assert result.version == sample_package.version
            mock_redis.get.assert_called_once_with("malifiscan:pkg:TEST-001")

    def test_get_from_redis_cache_miss(self, mock_redis):
        """Test cache miss from Redis."""
        mock_redis.get.return_value = None

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.get("NONEXISTENT")

            assert result is None
            mock_redis.get.assert_called_once()

    def test_put_to_redis(self, mock_redis, sample_package):
        """Test storing package in Redis cache."""
        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            cache.put("TEST-001", sample_package)

            mock_redis.set.assert_called_once()
            call_args = mock_redis.set.call_args
            assert call_args[0][0] == "malifiscan:pkg:TEST-001"

            # Verify the stored data is valid JSON with package data
            stored_data = json.loads(call_args[0][1])
            assert stored_data["name"] == sample_package.name

    def test_has_in_redis_exists(self, mock_redis):
        """Test has() when key exists in Redis."""
        mock_redis.exists.return_value = 1

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.has("TEST-001")

            assert result is True
            mock_redis.exists.assert_called_once_with("malifiscan:pkg:TEST-001")

    def test_has_in_redis_not_exists(self, mock_redis):
        """Test has() when key does not exist in Redis."""
        mock_redis.exists.return_value = 0

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.has("NONEXISTENT")

            assert result is False

    def test_purge_redis_cache(self, mock_redis):
        """Test purging all packages from Redis cache."""
        # Simulate 3 keys found
        mock_redis.scan_iter.return_value = iter(
            [
                "malifiscan:pkg:TEST-001",
                "malifiscan:pkg:TEST-002",
                "malifiscan:pkg:TEST-003",
            ]
        )
        mock_redis.delete.return_value = 3

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            count = cache.purge()

            assert count == 3
            mock_redis.scan_iter.assert_called_once_with(match="malifiscan:pkg:*")
            mock_redis.delete.assert_called_once()

    def test_size_with_redis(self, mock_redis):
        """Test getting cache size from Redis."""
        # Simulate 5 keys
        mock_redis.scan_iter.return_value = iter(
            ["key1", "key2", "key3", "key4", "key5"]
        )

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            size = cache.size()

            assert size == 5
            mock_redis.scan_iter.assert_called_once_with(match="malifiscan:pkg:*")

    def test_get_stats_with_redis(self, mock_redis):
        """Test getting cache statistics from Redis."""
        mock_redis.scan_iter.return_value = iter(["key1", "key2"])

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            stats = cache.get_stats()

            assert stats["backend"] == "redis"
            assert stats["redis_connected"] is True
            assert stats["total_packages"] == 2

    def test_redis_key_format(self, mock_redis):
        """Test that Redis keys are formatted correctly."""
        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(
                redis_url="redis://localhost:6379/0", redis_key_prefix="test:prefix:"
            )

            key = cache._redis_key("TEST-001")
            assert key == "test:prefix:TEST-001"

    def test_redis_error_handling_on_get(self, mock_redis):
        """Test error handling when Redis get() fails."""
        mock_redis.get.side_effect = Exception("Redis error")

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.get("TEST-001")

            # Should return None on error, not raise
            assert result is None

    def test_redis_error_handling_on_put(self, mock_redis, sample_package):
        """Test error handling when Redis set() fails."""
        mock_redis.set.side_effect = Exception("Redis error")

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")

            # Should not raise exception
            cache.put("TEST-001", sample_package)

    def test_redis_error_handling_on_has(self, mock_redis):
        """Test error handling when Redis exists() fails."""
        mock_redis.exists.side_effect = Exception("Redis error")

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            result = cache.has("TEST-001")

            # Should return False on error, not raise
            assert result is False

    def test_redis_error_handling_on_purge(self, mock_redis):
        """Test error handling when Redis purge fails."""
        mock_redis.scan_iter.side_effect = Exception("Redis error")

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            count = cache.purge()

            # Should return 0 on error, not raise
            assert count == 0

    def test_redis_error_handling_on_size(self, mock_redis):
        """Test error handling when Redis size check fails."""
        mock_redis.scan_iter.side_effect = Exception("Redis error")

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")
            size = cache.size()

            # Should return 0 on error, not raise
            assert size == 0


class TestPackageCacheRoundTrip:
    """Test complete cache operations (put and get)."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = MagicMock()
        mock.ping.return_value = True
        mock.get.return_value = None
        mock.set.return_value = True
        mock.exists.return_value = 0
        mock.delete.return_value = 0
        mock.scan_iter.return_value = iter([])
        return mock

    def test_redis_round_trip(self, mock_redis, sample_package):
        """Test storing and retrieving a package from Redis."""
        stored_data = None

        def mock_set(key, value):
            nonlocal stored_data
            stored_data = value
            return True

        def mock_get(key):
            return stored_data

        mock_redis.set.side_effect = mock_set
        mock_redis.get.side_effect = mock_get

        with patch("redis.from_url", return_value=mock_redis):
            cache = PackageCache(redis_url="redis://localhost:6379/0")

            # Store package
            cache.put("TEST-001", sample_package)

            # Retrieve package
            retrieved = cache.get("TEST-001")

            assert retrieved is not None
            assert retrieved.name == sample_package.name
            assert retrieved.version == sample_package.version
            assert retrieved.ecosystem == sample_package.ecosystem
            assert retrieved.advisory_id == sample_package.advisory_id
