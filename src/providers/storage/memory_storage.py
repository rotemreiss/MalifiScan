"""In-memory storage provider for testing and development."""

import asyncio
import copy
import logging
from typing import Any, Dict, List, Optional

from src.core.entities import MaliciousPackage, ScanResult
from src.core.interfaces import PackagesRegistryService, StorageService
from src.providers.exceptions import StorageError

logger = logging.getLogger(__name__)


class MemoryStorage(StorageService):
    """In-memory storage provider for testing and development."""

    def __init__(self, max_scan_results: int = 1000, clear_on_init: bool = False):
        """
        Initialize memory storage provider.

        Args:
            max_scan_results: Maximum number of scan results to keep in memory
            clear_on_init: Whether to clear existing data on initialization
        """
        self.max_scan_results = max_scan_results
        self._lock = asyncio.Lock()

        if clear_on_init or not hasattr(MemoryStorage, "_scan_results"):
            # Class-level storage to persist across instances in the same process
            MemoryStorage._scan_results: List[ScanResult] = []
            MemoryStorage._malicious_packages: Dict[str, MaliciousPackage] = {}

        logger.debug(
            f"Memory storage initialized with max_scan_results={max_scan_results}"
        )

    async def store_scan_result(
        self,
        scan_result: ScanResult,
        registry_service: PackagesRegistryService = None,
    ) -> bool:
        """
        Store a scan result in memory.

        Args:
            scan_result: The scan result to store

        Returns:
            True if stored successfully, False otherwise
        """
        logger.debug(f"Storing scan result: {scan_result.scan_id}")

        async with self._lock:
            try:
                # Create a deep copy to avoid reference issues
                result_copy = copy.deepcopy(scan_result)

                # Remove existing result with same scan_id if it exists
                MemoryStorage._scan_results = [
                    r
                    for r in MemoryStorage._scan_results
                    if r.scan_id != scan_result.scan_id
                ]

                # Add new result
                MemoryStorage._scan_results.append(result_copy)

                # Sort by timestamp (newest first)
                MemoryStorage._scan_results.sort(
                    key=lambda x: x.timestamp, reverse=True
                )

                # Trim to max size
                if len(MemoryStorage._scan_results) > self.max_scan_results:
                    MemoryStorage._scan_results = MemoryStorage._scan_results[
                        : self.max_scan_results
                    ]

                logger.debug(f"Successfully stored scan result: {scan_result.scan_id}")
                return True

            except Exception as e:
                logger.error(f"Failed to store scan result: {e}")
                raise StorageError(f"Failed to store scan result: {e}") from e

    async def get_scan_results(
        self, limit: Optional[int] = None, scan_id: Optional[str] = None
    ) -> List[ScanResult]:
        """
        Retrieve scan results from memory.

        Args:
            limit: Maximum number of results to return
            scan_id: Specific scan ID to retrieve

        Returns:
            List of scan results
        """
        logger.debug(f"Retrieving scan results (limit={limit}, scan_id={scan_id})")

        try:
            # Filter by scan_id if specified
            if scan_id:
                results = [
                    copy.deepcopy(r)
                    for r in MemoryStorage._scan_results
                    if r.scan_id == scan_id
                ]
            else:
                results = [copy.deepcopy(r) for r in MemoryStorage._scan_results]

            # Apply limit
            if limit and limit > 0:
                results = results[:limit]

            logger.debug(f"Retrieved {len(results)} scan results")
            return results

        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            raise StorageError(f"Failed to retrieve scan results: {e}") from e

    async def get_known_malicious_packages(self) -> List[MaliciousPackage]:
        """
        Get list of previously identified malicious packages.

        Returns:
            List of known malicious packages
        """
        logger.debug("Retrieving known malicious packages")

        try:
            packages = [
                copy.deepcopy(pkg) for pkg in MemoryStorage._malicious_packages.values()
            ]

            logger.debug(f"Retrieved {len(packages)} known malicious packages")
            return packages

        except Exception as e:
            logger.error(f"Failed to retrieve known malicious packages: {e}")
            raise StorageError(
                f"Failed to retrieve known malicious packages: {e}"
            ) from e

    async def store_malicious_packages(self, packages: List[MaliciousPackage]) -> bool:
        """
        Store malicious packages for future reference.

        Args:
            packages: List of malicious packages to store

        Returns:
            True if stored successfully, False otherwise
        """
        logger.debug(f"Storing {len(packages)} malicious packages")

        async with self._lock:
            try:
                new_count = 0

                for package in packages:
                    # Use package_identifier as key to avoid duplicates
                    if (
                        package.package_identifier
                        not in MemoryStorage._malicious_packages
                    ):
                        new_count += 1

                    # Store a deep copy
                    MemoryStorage._malicious_packages[package.package_identifier] = (
                        copy.deepcopy(package)
                    )

                logger.debug(
                    f"Successfully stored {len(packages)} malicious packages ({new_count} new)"
                )
                return True

            except Exception as e:
                logger.error(f"Failed to store malicious packages: {e}")
                raise StorageError(f"Failed to store malicious packages: {e}") from e

    async def get_scan_summary(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get scan summaries with basic metadata.

        This method is not supported by memory storage - scan results feature
        is only available with database storage.

        Args:
            limit: Maximum number of scan summaries to return

        Raises:
            NotImplementedError: Memory storage doesn't support scan summaries
        """
        raise NotImplementedError(
            "Scan results functionality is only supported by database storage. "
            "Please configure the application to use DatabaseStorage to access scan summaries."
        )

    async def health_check(self) -> bool:
        """
        Check if the memory storage is healthy and accessible.

        Returns:
            True if service is healthy, False otherwise
        """
        try:
            # Simple health check - verify we can access the storage
            _ = len(MemoryStorage._scan_results)
            _ = len(MemoryStorage._malicious_packages)

            logger.debug("Memory storage health check passed")
            return True

        except Exception as e:
            logger.error(f"Memory storage health check failed: {e}")
            return False

    async def clear_all_data(self) -> bool:
        """
        Clear all stored data. Useful for testing.

        Returns:
            True if cleared successfully, False otherwise
        """
        logger.debug("Clearing all data from memory storage")

        async with self._lock:
            try:
                MemoryStorage._scan_results.clear()
                MemoryStorage._malicious_packages.clear()

                logger.debug("Successfully cleared all data")
                return True

            except Exception as e:
                logger.error(f"Failed to clear data: {e}")
                return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        return {
            "type": "memory",
            "scan_results_count": len(MemoryStorage._scan_results),
            "malicious_packages_count": len(MemoryStorage._malicious_packages),
            "max_scan_results": self.max_scan_results,
            "memory_usage_bytes": self._estimate_memory_usage(),
        }

    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage in bytes (rough approximation)."""
        import sys

        total_size = 0
        try:
            total_size += sys.getsizeof(MemoryStorage._scan_results)
            for result in MemoryStorage._scan_results:
                total_size += sys.getsizeof(result)

            total_size += sys.getsizeof(MemoryStorage._malicious_packages)
            for package in MemoryStorage._malicious_packages.values():
                total_size += sys.getsizeof(package)
        except Exception as e:
            # If size calculation fails, return the partial size we have so far
            logging.debug(f"Error during memory size calculation: {e}")

        return total_size
