"""No-cache provider for when caching is disabled."""

import logging
from typing import Optional

from .cache_provider import CacheProvider

logger = logging.getLogger(__name__)


class NoCacheProvider(CacheProvider):
    """No-op cache provider for when caching is disabled."""

    def __init__(self):
        """Initialize no-cache provider."""
        logger.debug("No-cache provider initialized (caching disabled)")

    def get(self, key: str) -> Optional[str]:
        """
        Get operation (no-op).

        Args:
            key: The cache key

        Returns:
            None (no caching)
        """
        return None

    def put(self, key: str, value: str) -> None:
        """
        Put operation (no-op).

        Args:
            key: The cache key
            value: The value to cache
        """
        pass

    def has(self, key: str) -> bool:
        """
        Check if key exists (no-op).

        Args:
            key: The cache key

        Returns:
            False (no caching)
        """
        return False

    def delete(self, key: str) -> bool:
        """
        Delete operation (no-op).

        Args:
            key: The cache key

        Returns:
            False (nothing to delete)
        """
        return False

    def scan_keys(self, pattern: str):
        """
        Scan operation (no-op).

        Args:
            pattern: The key pattern

        Returns:
            Empty iterator
        """
        return iter([])

    def delete_many(self, keys: list) -> int:
        """
        Delete many operation (no-op).

        Args:
            keys: List of keys

        Returns:
            0 (nothing deleted)
        """
        return 0

    def is_connected(self) -> bool:
        """
        Check connection status.

        Returns:
            True (no-cache is always "connected")
        """
        return True

    async def ping(self) -> bool:
        """
        Ping operation (no-op).

        Returns:
            True (always healthy in no-cache mode)
        """
        return True

    def get_backend_name(self) -> str:
        """
        Get backend name.

        Returns:
            'none' for no-cache
        """
        return "none"
