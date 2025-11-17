"""Unit tests for PackageCache."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.cache.package_cache import PackageCache
from src.providers.cache import RedisCacheProvider


class TestPackageCacheWithNoCacheProvider:
    """Test PackageCache with NoCacheProvider (cache disabled)."""

    def test_init_with_no_cache_provider(self, no_cache_provider):
        """Test initialization with no-cache provider."""
        cache = PackageCache(provider=no_cache_provider)

        assert cache.provider is not None
        assert cache.get_cache_backend() == "none"
        assert cache.is_cache_enabled() is False

    def test_get_returns_none_when_no_cache(
        self, no_cache_provider, sample_malicious_package
    ):
        """Test that get() returns None when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)

        result = cache.get("TEST-001")
        assert result is None

    def test_put_does_nothing_when_no_cache(
        self, no_cache_provider, sample_malicious_package
    ):
        """Test that put() does nothing when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)

        # Should not raise an error
        cache.put("TEST-001", sample_malicious_package)

        # Should still return None when trying to get
        result = cache.get("TEST-001")
        assert result is None

    def test_has_returns_false_when_no_cache(self, no_cache_provider):
        """Test that has() returns False when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)

        assert cache.has("TEST-001") is False

    def test_size_returns_zero_when_no_cache(self, no_cache_provider):
        """Test that size() returns 0 when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)

        assert cache.size() == 0

    def test_purge_returns_zero_when_no_cache(self, no_cache_provider):
        """Test that purge() returns 0 when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)

        count = cache.purge()
        assert count == 0

    def test_get_stats_when_no_cache(self, no_cache_provider):
        """Test that get_stats() returns no-cache information."""
        cache = PackageCache(provider=no_cache_provider)

        stats = cache.get_stats()
        assert stats["total_packages"] == 0
        assert stats["backend"] == "none"
        assert stats["cache_enabled"] is False


class TestPackageCacheWithMockRedisProvider:
    """Test PackageCache with mock Redis provider."""

    def test_get_from_redis_cache_hit(
        self, mock_redis_provider, sample_malicious_package
    ):
        """Test successful retrieval from Redis cache."""
        package_json = json.dumps(sample_malicious_package.to_dict())
        mock_redis_provider.get.return_value = package_json

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.get("TEST-PYPI-001")

        assert result is not None
        assert result.name == sample_malicious_package.name
        assert result.version == sample_malicious_package.version
        mock_redis_provider.get.assert_called_once_with("malifiscan:pkg:TEST-PYPI-001")

    def test_get_from_redis_cache_miss(self, mock_redis_provider):
        """Test cache miss from Redis."""
        mock_redis_provider.get.return_value = None

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.get("NONEXISTENT")

        assert result is None
        mock_redis_provider.get.assert_called_once_with("malifiscan:pkg:NONEXISTENT")

    def test_put_to_redis(self, mock_redis_provider, sample_malicious_package):
        """Test storing package in Redis cache."""
        cache = PackageCache(provider=mock_redis_provider)
        cache.put("TEST-PYPI-001", sample_malicious_package)

        mock_redis_provider.put.assert_called_once()
        call_args = mock_redis_provider.put.call_args
        assert call_args[0][0] == "malifiscan:pkg:TEST-PYPI-001"
        # Verify the JSON contains the package data
        stored_data = json.loads(call_args[0][1])
        assert stored_data["name"] == sample_malicious_package.name

    def test_has_in_redis_exists(self, mock_redis_provider):
        """Test has() when key exists in Redis."""
        mock_redis_provider.has.return_value = True

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.has("TEST-001")

        assert result is True
        mock_redis_provider.has.assert_called_once_with("malifiscan:pkg:TEST-001")

    def test_has_in_redis_not_exists(self, mock_redis_provider):
        """Test has() when key does not exist in Redis."""
        mock_redis_provider.has.return_value = False

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.has("TEST-001")

        assert result is False
        mock_redis_provider.has.assert_called_once_with("malifiscan:pkg:TEST-001")

    def test_purge_redis_cache(self, mock_redis_provider):
        """Test purging all packages from Redis cache."""
        # Simulate 3 keys found
        mock_redis_provider.scan_keys.return_value = iter(
            [
                "malifiscan:pkg:TEST-001",
                "malifiscan:pkg:TEST-002",
                "malifiscan:pkg:TEST-003",
            ]
        )
        mock_redis_provider.delete_many.return_value = 3

        cache = PackageCache(provider=mock_redis_provider)
        count = cache.purge()

        assert count == 3
        mock_redis_provider.scan_keys.assert_called_once_with("malifiscan:pkg:*")
        mock_redis_provider.delete_many.assert_called_once()

    def test_size_with_redis(self, mock_redis_provider):
        """Test getting cache size from Redis."""
        # Simulate 5 keys
        mock_redis_provider.scan_keys.return_value = iter(
            ["key1", "key2", "key3", "key4", "key5"]
        )

        cache = PackageCache(provider=mock_redis_provider)
        size = cache.size()

        assert size == 5
        mock_redis_provider.scan_keys.assert_called_once_with("malifiscan:pkg:*")

    def test_get_stats_with_redis(self, mock_redis_provider):
        """Test getting cache statistics from Redis."""
        mock_redis_provider.scan_keys.return_value = iter(["key1", "key2"])
        mock_redis_provider.is_connected.return_value = True

        cache = PackageCache(provider=mock_redis_provider)
        stats = cache.get_stats()

        assert stats["total_packages"] == 2
        assert stats["backend"] == "redis"
        assert stats["cache_enabled"] is True

    def test_custom_key_prefix(self, mock_redis_provider, sample_malicious_package):
        """Test PackageCache with custom key prefix."""
        cache = PackageCache(provider=mock_redis_provider, key_prefix="custom:prefix:")
        cache.get("TEST-001")

        mock_redis_provider.get.assert_called_once_with("custom:prefix:TEST-001")

    def test_redis_error_handling_on_get(self, mock_redis_provider):
        """Test error handling when get() fails."""
        mock_redis_provider.get.side_effect = Exception("Redis connection error")

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.get("TEST-001")

        assert result is None

    def test_redis_error_handling_on_put(
        self, mock_redis_provider, sample_malicious_package
    ):
        """Test error handling when put() fails."""
        mock_redis_provider.put.side_effect = Exception("Redis write error")

        cache = PackageCache(provider=mock_redis_provider)
        # Should not raise, just log error
        cache.put("TEST-001", sample_malicious_package)

    def test_redis_error_handling_on_has(self, mock_redis_provider):
        """Test error handling when has() fails."""
        mock_redis_provider.has.side_effect = Exception("Redis error")

        cache = PackageCache(provider=mock_redis_provider)
        result = cache.has("TEST-001")

        assert result is False

    def test_redis_error_handling_on_purge(self, mock_redis_provider):
        """Test error handling when purge() fails."""
        mock_redis_provider.scan_keys.side_effect = Exception("Redis scan error")

        cache = PackageCache(provider=mock_redis_provider)
        count = cache.purge()

        assert count == 0

    def test_redis_error_handling_on_size(self, mock_redis_provider):
        """Test error handling when size() fails."""
        mock_redis_provider.scan_keys.side_effect = Exception("Redis scan error")

        cache = PackageCache(provider=mock_redis_provider)
        size = cache.size()

        assert size == 0


class TestPackageCacheRoundTrip:
    """Test complete cache operations (put and get)."""

    def test_redis_round_trip(self, sample_malicious_package):
        """Test storing and retrieving a package from mock Redis."""
        # Create a mock provider that actually stores data
        stored_data = {}

        mock_provider = MagicMock()
        mock_provider.get_backend_name.return_value = "redis"
        mock_provider.is_connected.return_value = True
        mock_provider.get.side_effect = lambda key: stored_data.get(key)
        mock_provider.put.side_effect = lambda key, value: stored_data.update(
            {key: value}
        )
        mock_provider.has.side_effect = lambda key: key in stored_data

        cache = PackageCache(provider=mock_provider)

        # Store package
        cache.put("TEST-PYPI-001", sample_malicious_package)

        # Retrieve package
        retrieved = cache.get("TEST-PYPI-001")

        assert retrieved is not None
        assert retrieved.name == sample_malicious_package.name
        assert retrieved.version == sample_malicious_package.version
        assert retrieved.ecosystem == sample_malicious_package.ecosystem
        assert retrieved.advisory_id == sample_malicious_package.advisory_id


class TestPackageCacheHealthCheck:
    """Test PackageCache health check and status methods."""

    def test_is_cache_enabled_with_no_cache(self, no_cache_provider):
        """Test is_cache_enabled() returns False with no-cache provider."""
        cache = PackageCache(provider=no_cache_provider)
        assert cache.is_cache_enabled() is False

    def test_is_cache_enabled_with_redis(self, mock_redis_provider):
        """Test is_cache_enabled() returns True when Redis is connected."""
        mock_redis_provider.is_connected.return_value = True
        cache = PackageCache(provider=mock_redis_provider)
        assert cache.is_cache_enabled() is True

    def test_get_cache_backend_with_no_cache(self, no_cache_provider):
        """Test get_cache_backend() returns 'none' with no-cache provider."""
        cache = PackageCache(provider=no_cache_provider)
        assert cache.get_cache_backend() == "none"

    def test_get_cache_backend_with_redis(self, mock_redis_provider):
        """Test get_cache_backend() returns 'redis' with Redis provider."""
        cache = PackageCache(provider=mock_redis_provider)
        assert cache.get_cache_backend() == "redis"

    @pytest.mark.asyncio
    async def test_health_check_with_no_cache(self, no_cache_provider):
        """Test health_check() returns healthy dict when cache is disabled."""
        cache = PackageCache(provider=no_cache_provider)
        result = await cache.health_check()

        assert result["healthy"] is True
        assert result["enabled"] is False
        assert result["backend"] == "none"

    @pytest.mark.asyncio
    async def test_health_check_with_redis_success(self, mock_redis_provider):
        """Test health_check() returns healthy dict when Redis ping succeeds."""
        cache = PackageCache(provider=mock_redis_provider)
        result = await cache.health_check()

        assert result["healthy"] is True
        assert result["enabled"] is True
        assert result["backend"] == "redis"
        mock_redis_provider.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_with_redis_failure(self, mock_redis_provider):
        """Test health_check() returns unhealthy dict when Redis ping fails."""
        from unittest.mock import AsyncMock

        mock_redis_provider.ping = AsyncMock(return_value=False)

        cache = PackageCache(provider=mock_redis_provider)
        result = await cache.health_check()

        assert result["healthy"] is False
        assert result["enabled"] is True
        assert result["backend"] == "redis"


class TestRedisCacheProvider:
    """Test RedisCacheProvider directly."""

    def test_redis_provider_successful_connection(self):
        """Test Redis provider connects successfully."""
        mock_redis_client = MagicMock()
        mock_redis_client.ping.return_value = True

        # Mock the redis module at the point where it's imported in RedisCacheProvider
        mock_redis_module = MagicMock()
        mock_redis_module.from_url.return_value = mock_redis_client

        with patch.dict("sys.modules", {"redis": mock_redis_module}):
            provider = RedisCacheProvider(redis_url="redis://localhost:6379/0")

            assert provider.is_connected() is True
            assert provider.get_backend_name() == "redis"
            mock_redis_client.ping.assert_called_once()

    def test_redis_provider_connection_failure(self):
        """Test Redis provider handles connection failure gracefully."""
        mock_redis_module = MagicMock()
        mock_redis_module.from_url.side_effect = ConnectionError("Connection refused")

        with patch.dict("sys.modules", {"redis": mock_redis_module}):
            provider = RedisCacheProvider(redis_url="redis://localhost:6379/0")

            assert provider.is_connected() is False
            assert provider.get_backend_name() == "redis"

    def test_redis_provider_no_url(self):
        """Test Redis provider with no URL provided."""
        provider = RedisCacheProvider(redis_url=None)

        assert provider.is_connected() is False
        assert provider.get_backend_name() == "redis"


class TestNoCacheProvider:
    """Test NoCacheProvider directly."""

    def test_no_cache_provider_operations(self, no_cache_provider):
        """Test all NoCacheProvider operations."""
        assert no_cache_provider.get("key") is None
        assert no_cache_provider.has("key") is False
        assert no_cache_provider.delete("key") is False
        assert no_cache_provider.delete_many(["key1", "key2"]) == 0
        assert list(no_cache_provider.scan_keys("*")) == []
        assert no_cache_provider.is_connected() is True
        assert no_cache_provider.get_backend_name() == "none"

        # Put should not raise
        no_cache_provider.put("key", "value")

    @pytest.mark.asyncio
    async def test_no_cache_provider_ping(self, no_cache_provider):
        """Test NoCacheProvider ping always returns True."""
        result = await no_cache_provider.ping()
        assert result is True
