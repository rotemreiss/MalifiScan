"""Package Cache Service Interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ..entities import MaliciousPackage


class PackageCacheService(ABC):
    """Interface for package cache service operations."""

    @abstractmethod
    def get(self, advisory_id: str) -> Optional[MaliciousPackage]:
        """
        Retrieve a package from cache.

        Args:
            advisory_id: The advisory ID to look up

        Returns:
            MaliciousPackage if found, None otherwise
        """
        pass

    @abstractmethod
    def put(self, advisory_id: str, package: MaliciousPackage) -> None:
        """
        Store a package in cache.

        Args:
            advisory_id: The advisory ID key
            package: The malicious package to cache
        """
        pass

    @abstractmethod
    def has(self, advisory_id: str) -> bool:
        """
        Check if a package exists in cache.

        Args:
            advisory_id: The advisory ID to check

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    def size(self) -> int:
        """
        Get the number of cached packages.

        Returns:
            Number of packages in cache
        """
        pass

    @abstractmethod
    def purge(self) -> int:
        """
        Clear all cached packages.

        Returns:
            Number of packages removed
        """
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check if cache service is healthy.

        Returns:
            Dict with health status including enabled, backend, and healthy fields
        """
        pass
