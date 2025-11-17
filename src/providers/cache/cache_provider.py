"""Cache provider interface for backend implementations."""

from abc import ABC, abstractmethod
from typing import Optional


class CacheProvider(ABC):
    """Interface for cache backend providers."""

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a value from cache by key.

        Args:
            key: The cache key

        Returns:
            Cached value as string if found, None otherwise
        """
        pass

    @abstractmethod
    def put(self, key: str, value: str) -> None:
        """
        Store a value in cache.

        Args:
            key: The cache key
            value: The value to cache (as string)
        """
        pass

    @abstractmethod
    def has(self, key: str) -> bool:
        """
        Check if a key exists in cache.

        Args:
            key: The cache key

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete a key from cache.

        Args:
            key: The cache key

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def scan_keys(self, pattern: str):
        """
        Scan for keys matching a pattern.

        Args:
            pattern: The key pattern to match

        Returns:
            Iterator of matching keys
        """
        pass

    @abstractmethod
    def delete_many(self, keys: list) -> int:
        """
        Delete multiple keys from cache.

        Args:
            keys: List of keys to delete

        Returns:
            Number of keys deleted
        """
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """
        Check if provider is connected and operational.

        Returns:
            True if connected, False otherwise
        """
        pass

    @abstractmethod
    async def ping(self) -> bool:
        """
        Ping the cache backend to check health.

        Returns:
            True if backend responds, False otherwise
        """
        pass

    @abstractmethod
    def get_backend_name(self) -> str:
        """
        Get the name of the cache backend.

        Returns:
            Backend name (e.g., 'redis', 'memcached', 'none')
        """
        pass
