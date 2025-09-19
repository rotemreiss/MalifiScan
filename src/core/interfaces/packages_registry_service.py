"""Packages registry service interface."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

from src.core.entities import MaliciousPackage


class PackagesRegistryService(ABC):
    """Abstract interface for package registry providers."""
    
    @abstractmethod
    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Block malicious packages in the registry.
        
        Args:
            packages: List of malicious packages to block
            
        Returns:
            List of package identifiers that were successfully blocked
            
        Raises:
            RegistryError: If blocking operation fails
        """
        pass
    
    @abstractmethod
    async def block_package(self, package: MaliciousPackage) -> bool:
        """
        Block a single malicious package in the registry.
        
        Args:
            package: Malicious package to block
            
        Returns:
            True if successfully blocked, False otherwise
            
        Raises:
            RegistryError: If blocking operation fails
        """
        pass
    
    @abstractmethod
    async def check_existing_packages(self, packages: List[MaliciousPackage]) -> List[MaliciousPackage]:
        """
        Check which packages are already present/blocked in the registry.
        
        Args:
            packages: List of packages to check
            
        Returns:
            List of packages that are already present in the registry
            
        Raises:
            RegistryError: If check operation fails
        """
        pass

    @abstractmethod
    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Unblock packages in the registry (for testing or false positives).
        
        Args:
            packages: List of packages to unblock
            
        Returns:
            List of package identifiers that were successfully unblocked
            
        Raises:
            RegistryError: If unblocking operation fails
        """
        pass
    
    @abstractmethod
    async def search_packages(self, package_name: str, ecosystem: str) -> List[Dict[str, Any]]:
        """
        Search for packages in the registry.
        
        Args:
            package_name: Name of package to search for
            ecosystem: Package ecosystem (npm, PyPI, etc.)
            
        Returns:
            List of package information dictionaries
            
        Raises:
            RegistryError: If search operation fails
        """
        pass
    
    @abstractmethod
    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """
        Check if a package is blocked in the registry.
        
        Args:
            package: Package to check
            
        Returns:
            True if package is blocked, False otherwise
            
        Raises:
            RegistryError: If check operation fails
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the registry service is healthy and accessible.
        
        Returns:
            True if service is healthy, False otherwise
        """
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """
        Close the registry connection and cleanup resources.
        """
        pass