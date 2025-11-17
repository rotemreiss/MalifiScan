"""Redis cache provider implementation."""

import logging
from typing import Optional

from .cache_provider import CacheProvider

logger = logging.getLogger(__name__)


class RedisCacheProvider(CacheProvider):
    """Redis backend provider for cache operations."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
    ):
        """
        Initialize Redis cache provider.

        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379/0)
        """
        self._redis = None
        self._connected = False

        if redis_url:
            try:
                import redis

                self._redis = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                self._redis.ping()
                self._connected = True
                logger.debug(f"✅ Connected to Redis at {redis_url}")
            except ImportError:
                logger.warning("redis package not installed, Redis cache unavailable")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")

    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a value from Redis by key.

        Args:
            key: The cache key

        Returns:
            Cached value as string if found, None otherwise
        """
        if not self._connected:
            return None

        try:
            return self._redis.get(key)
        except Exception as e:
            logger.warning(f"Failed to get key {key} from Redis: {e}")
            return None

    def put(self, key: str, value: str) -> None:
        """
        Store a value in Redis.

        Args:
            key: The cache key
            value: The value to cache (as string)
        """
        if not self._connected:
            return

        try:
            self._redis.set(key, value)
        except Exception as e:
            logger.error(f"Failed to set key {key} in Redis: {e}")

    def has(self, key: str) -> bool:
        """
        Check if a key exists in Redis.

        Args:
            key: The cache key

        Returns:
            True if exists, False otherwise
        """
        if not self._connected:
            return False

        try:
            return self._redis.exists(key) > 0
        except Exception as e:
            logger.warning(f"Failed to check key {key} in Redis: {e}")
            return False

    def delete(self, key: str) -> bool:
        """
        Delete a key from Redis.

        Args:
            key: The cache key

        Returns:
            True if deleted, False if not found
        """
        if not self._connected:
            return False

        try:
            return self._redis.delete(key) > 0
        except Exception as e:
            logger.warning(f"Failed to delete key {key} from Redis: {e}")
            return False

    def scan_keys(self, pattern: str):
        """
        Scan for keys matching a pattern in Redis.

        Args:
            pattern: The key pattern to match

        Returns:
            Iterator of matching keys
        """
        if not self._connected:
            return iter([])

        try:
            return self._redis.scan_iter(match=pattern)
        except Exception as e:
            logger.warning(f"Failed to scan keys with pattern {pattern}: {e}")
            return iter([])

    def delete_many(self, keys: list) -> int:
        """
        Delete multiple keys from Redis.

        Args:
            keys: List of keys to delete

        Returns:
            Number of keys deleted
        """
        if not self._connected or not keys:
            return 0

        try:
            return self._redis.delete(*keys)
        except Exception as e:
            logger.error(f"Failed to delete multiple keys from Redis: {e}")
            return 0

    def is_connected(self) -> bool:
        """
        Check if provider is connected to Redis.

        Returns:
            True if connected, False otherwise
        """
        return self._connected

    async def ping(self) -> bool:
        """
        Ping Redis to check health.

        Returns:
            True if Redis responds, False otherwise
        """
        if not self._connected:
            return False

        try:
            self._redis.ping()
            return True
        except Exception as e:
            logger.warning(f"Redis ping failed: {e}")
            return False

    def get_backend_name(self) -> str:
        """
        Get the name of the cache backend.

        Returns:
            Backend name 'redis'
        """
        return "redis"
