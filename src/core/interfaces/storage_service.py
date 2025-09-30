"""Storage service interface."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

from src.core.entities import MaliciousPackage, ScanResult

if TYPE_CHECKING:
    from .packages_registry_service import PackagesRegistryService


class StorageService(ABC):
    """Abstract interface for storage providers."""

    @abstractmethod
    async def store_scan_result(
        self,
        scan_result: ScanResult,
        registry_service: "PackagesRegistryService" = None,
    ) -> bool:
        """
        Store a scan result in the storage backend.

        Args:
            scan_result: The scan result to store
            registry_service: The registry service used for the scan (optional)

        Returns:
            True if stored successfully, False otherwise

        Raises:
            StorageError: If storage operation fails
        """
        pass

    @abstractmethod
    async def get_scan_results(
        self, limit: Optional[int] = None, scan_id: Optional[str] = None
    ) -> List[ScanResult]:
        """
        Retrieve scan results from storage.

        Args:
            limit: Maximum number of results to return
            scan_id: Specific scan ID to retrieve

        Returns:
            List of scan results

        Raises:
            StorageError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def get_known_malicious_packages(self) -> List[MaliciousPackage]:
        """
        Get list of previously identified malicious packages.

        Returns:
            List of known malicious packages

        Raises:
            StorageError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def store_malicious_packages(self, packages: List[MaliciousPackage]) -> bool:
        """
        Store malicious packages for future reference.

        Args:
            packages: List of malicious packages to store

        Returns:
            True if stored successfully, False otherwise

        Raises:
            StorageError: If storage operation fails
        """
        pass

    @abstractmethod
    async def get_scan_summary(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get scan summaries with basic metadata.

        Args:
            limit: Maximum number of scan summaries to return

        Returns:
            List of dictionaries with scan summary data:
            - scan_id: str
            - timestamp: datetime
            - status: str
            - packages_scanned: int
            - malicious_packages_count: int
            - findings_count: int
            - execution_duration_seconds: float

        Raises:
            StorageError: If retrieval operation fails
            NotImplementedError: If storage provider doesn't support scan summaries
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the storage service is healthy and accessible.

        Returns:
            True if service is healthy, False otherwise
        """
        pass
