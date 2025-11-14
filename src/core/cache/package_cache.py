"""Persistent cache for malicious packages."""

import json
import logging
from typing import Dict, Optional

from ..entities import MaliciousPackage

logger = logging.getLogger(__name__)


class PackageCache:
    """Redis-based persistent cache for malicious packages with no-cache fallback."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        redis_key_prefix: str = "malifiscan:pkg:",
    ):
        """
        Initialize the package cache.

        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379/0)
            redis_key_prefix: Prefix for Redis keys
        """
        self.redis_key_prefix = redis_key_prefix
        self._redis = None
        self._use_cache = False

        # Try to connect to Redis
        if redis_url:
            try:
                import redis

                self._redis = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                self._redis.ping()
                self._use_cache = True
                logger.debug(f"✅ Connected to Redis cache at {redis_url}")
            except ImportError:
                logger.warning("redis package not installed, caching disabled")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}, caching disabled")

        if not self._use_cache:
            logger.info("⚠️ Cache disabled - all packages will be fetched from source")

    def _load_cache(self) -> None:
        """Load cache from disk (no-op for Redis-only cache)."""
        # No file-based cache - this is a no-op
        pass

    def _save_cache(self) -> None:
        """Save cache to disk (no-op for Redis-only cache)."""
        # No file-based cache - this is a no-op
        pass

    def _redis_key(self, osv_id: str) -> str:
        """Get Redis key for OSV ID."""
        return f"{self.redis_key_prefix}{osv_id}"

    def get(self, osv_id: str) -> Optional[MaliciousPackage]:
        """
        Get a package from cache by OSV ID.

        Args:
            osv_id: OSV vulnerability ID (e.g., MAL-2025-170599)

        Returns:
            MaliciousPackage if found in cache, None otherwise
        """
        if not self._use_cache:
            return None

        try:
            key = self._redis_key(osv_id)
            data = self._redis.get(key)
            if data:
                return MaliciousPackage.from_dict(json.loads(data))
            return None
        except Exception as e:
            logger.warning(f"Failed to get cached package {osv_id}: {e}")
            return None

    def put(self, osv_id: str, package: MaliciousPackage) -> None:
        """
        Store a package in cache.

        Args:
            osv_id: OSV vulnerability ID (e.g., MAL-2025-170599)
            package: MaliciousPackage to cache
        """
        if not self._use_cache:
            return

        try:
            package_dict = package.to_dict()
            key = self._redis_key(osv_id)
            # Store in Redis with no expiration (persist until explicitly purged)
            self._redis.set(key, json.dumps(package_dict))
        except Exception as e:
            logger.error(f"Failed to cache package {osv_id}: {e}")

    def has(self, osv_id: str) -> bool:
        """
        Check if package exists in cache.

        Args:
            osv_id: OSV vulnerability ID (e.g., MAL-2025-170599)

        Returns:
            True if package is in cache, False otherwise
        """
        if not self._use_cache:
            return False

        try:
            key = self._redis_key(osv_id)
            return self._redis.exists(key) > 0
        except Exception as e:
            logger.warning(f"Failed to check cache for {osv_id}: {e}")
            return False

    def purge(self) -> int:
        """
        Purge all cached packages.

        Returns:
            Number of packages removed from cache
        """
        if not self._use_cache:
            return 0

        try:
            # Find all keys with our prefix and delete them
            pattern = f"{self.redis_key_prefix}*"
            keys = list(self._redis.scan_iter(match=pattern))
            count = len(keys)
            if count > 0:
                self._redis.delete(*keys)
            logger.info(f"Purged {count} packages from Redis cache")
            return count
        except Exception as e:
            logger.error(f"Failed to purge cache: {e}")
            return 0

    def size(self) -> int:
        """
        Get number of packages in cache.

        Returns:
            Number of cached packages
        """
        if not self._use_cache:
            return 0

        try:
            pattern = f"{self.redis_key_prefix}*"
            return sum(1 for _ in self._redis.scan_iter(match=pattern))
        except Exception as e:
            logger.warning(f"Failed to get cache size: {e}")
            return 0

    def get_stats(self) -> Dict[str, any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            if self._use_cache:
                return {
                    "total_packages": self.size(),
                    "backend": "redis",
                    "redis_connected": True,
                }
            else:
                return {
                    "total_packages": 0,
                    "backend": "none",
                    "cache_enabled": False,
                }
        except Exception as e:
            logger.warning(f"Failed to get cache stats: {e}")
            return {"total_packages": 0, "backend": "unknown", "error": str(e)}
