"""Persistent cache for malicious packages."""

import json
import logging
from typing import Any, Dict, Optional

from ...providers.cache import CacheProvider
from ..entities import MaliciousPackage
from ..interfaces import PackageCacheService

logger = logging.getLogger(__name__)


class PackageCache(PackageCacheService):
    """Package cache service with pluggable backend providers."""

    def __init__(
        self,
        provider: CacheProvider,
        key_prefix: str = "malifiscan:pkg:",
    ):
        """
        Initialize the package cache.

        Args:
            provider: Cache backend provider (Redis, NoCache, etc.)
            key_prefix: Prefix for cache keys
        """
        self.provider = provider
        self.key_prefix = key_prefix
        logger.debug(
            f"PackageCache initialized with {provider.get_backend_name()} backend"
        )

    def _cache_key(self, osv_id: str) -> str:
        """Get cache key for OSV ID."""
        return f"{self.key_prefix}{osv_id}"

    def get(self, osv_id: str) -> Optional[MaliciousPackage]:
        """
        Get a package from cache by OSV ID.

        Args:
            osv_id: OSV vulnerability ID (e.g., MAL-2025-170599)

        Returns:
            MaliciousPackage if found in cache, None otherwise
        """
        try:
            key = self._cache_key(osv_id)
            data = self.provider.get(key)
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
        try:
            package_dict = package.to_dict()
            key = self._cache_key(osv_id)
            self.provider.put(key, json.dumps(package_dict))
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
        try:
            key = self._cache_key(osv_id)
            return self.provider.has(key)
        except Exception as e:
            logger.warning(f"Failed to check cache for {osv_id}: {e}")
            return False

    def purge(self) -> int:
        """
        Purge all cached packages.

        Returns:
            Number of packages removed from cache
        """
        try:
            pattern = f"{self.key_prefix}*"
            keys = list(self.provider.scan_keys(pattern))
            count = len(keys)
            if count > 0:
                self.provider.delete_many(keys)
            logger.info(
                f"Purged {count} packages from {self.provider.get_backend_name()} cache"
            )
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
        try:
            pattern = f"{self.key_prefix}*"
            return sum(1 for _ in self.provider.scan_keys(pattern))
        except Exception as e:
            logger.warning(f"Failed to get cache size: {e}")
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            backend = self.provider.get_backend_name()
            is_connected = self.provider.is_connected()

            return {
                "total_packages": self.size(),
                "backend": backend,
                "cache_enabled": is_connected and backend != "none",
            }
        except Exception as e:
            logger.warning(f"Failed to get cache stats: {e}")
            return {"total_packages": 0, "backend": "unknown", "error": str(e)}

    def is_cache_enabled(self) -> bool:
        """
        Check if cache is enabled and working.

        Returns:
            True if cache backend is connected, False otherwise
        """
        backend = self.provider.get_backend_name()
        return self.provider.is_connected() and backend != "none"

    def get_cache_backend(self) -> str:
        """
        Get the cache backend type.

        Returns:
            Backend name (e.g., 'redis', 'none')
        """
        return self.provider.get_backend_name()

    async def health_check(self) -> Dict[str, Any]:
        """
        Check if cache service is healthy.

        Returns:
            Dict with health status details including enabled, backend, and healthy fields
        """
        backend = self.provider.get_backend_name()
        cache_enabled = backend != "none"
        cache_healthy = await self.provider.ping()

        # Return structured data for health management
        return {
            "enabled": cache_enabled,
            "backend": backend,
            "healthy": cache_healthy,
        }
