"""Storage service interface."""

from abc import ABC, abstractmethod
from typing import List, Optional

from src.core.entities import ScanResult, MaliciousPackage


class StorageService(ABC):
    """Abstract interface for storage providers."""
    
    @abstractmethod
    async def store_scan_result(self, scan_result: ScanResult) -> bool:
        """
        Store a scan result in the storage backend.
        
        Args:
            scan_result: The scan result to store
            
        Returns:
            True if stored successfully, False otherwise
            
        Raises:
            StorageError: If storage operation fails
        """
        pass
    
    @abstractmethod
    async def get_scan_results(
        self, 
        limit: Optional[int] = None,
        scan_id: Optional[str] = None
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
    async def health_check(self) -> bool:
        """
        Check if the storage service is healthy and accessible.
        
        Returns:
            True if service is healthy, False otherwise
        """
        pass