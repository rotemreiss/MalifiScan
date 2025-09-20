"""Null registry service for disabled package registry."""

import logging
from typing import List

from ...core.interfaces import PackagesRegistryService
from ...core.entities import MaliciousPackage


logger = logging.getLogger(__name__)


class NullRegistry(PackagesRegistryService):
    """Null registry service that does nothing."""
    
    def __init__(self):
        """Initialize null registry."""
        self.name = "NullRegistry"
    
    async def check_existing_packages(self, packages: List[MaliciousPackage]) -> List[MaliciousPackage]:
        """
        Check existing packages (no-op).
        
        Args:
            packages: List of packages to check
            
        Returns:
            Empty list (no packages are considered existing)
        """
        logger.debug(f"NullRegistry: Would check {len(packages)} packages (registry disabled)")
        return []
    
    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Block packages (no-op).
        
        Args:
            packages: List of packages to block
            
        Returns:
            Empty list (no packages blocked)
        """
        logger.debug(f"NullRegistry: Would block {len(packages)} packages (registry disabled)")
        return []
    
    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Unblock packages (no-op).
        
        Args:
            packages: List of packages to unblock
            
        Returns:
            Empty list (no packages unblocked)
        """
        logger.debug(f"NullRegistry: Would unblock {len(packages)} packages (registry disabled)")
        return []
    
    async def block_package(self, package: MaliciousPackage) -> bool:
        """
        Block a single package (no-op).
        
        Args:
            package: Package to block
            
        Returns:
            False (no package blocked)
        """
        logger.debug(f"NullRegistry: Would block package {package.name} (registry disabled)")
        return False
    
    async def search_packages(self, package_name: str, ecosystem: str) -> List[dict]:
        """
        Search for packages (no-op).
        
        Args:
            package_name: Name of package to search for
            ecosystem: Package ecosystem
            
        Returns:
            Empty list (no packages found)
        """
        logger.debug(f"NullRegistry: Would search for {package_name} in {ecosystem} (registry disabled)")
        return []
    
    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """
        Check if package is blocked (no-op).
        
        Args:
            package: Package to check
            
        Returns:
            False (no packages are blocked)
        """
        logger.debug(f"NullRegistry: Would check if {package.name} is blocked (registry disabled)")
        return False
    
    def get_registry_name(self) -> str:
        """
        Get registry name.
        
        Returns:
            Registry name
        """
        return "Null Registry (Disabled)"
    
    async def discover_repositories_by_ecosystem(self, ecosystem: str) -> List[str]:
        """
        Discover repositories (no-op).
        
        Args:
            ecosystem: Package ecosystem
            
        Returns:
            Empty list (no repositories)
        """
        logger.debug(f"NullRegistry: Would discover repositories for {ecosystem} (registry disabled)")
        return []
    
    async def close(self) -> None:
        """
        Close registry connection (no-op).
        """
        logger.debug("NullRegistry: Would close connection (registry disabled)")
        pass
    
    async def health_check(self) -> bool:
        """
        Check service health.
        
        Returns:
            True (always healthy)
        """
        return True
    
    def __str__(self) -> str:
        return "NullRegistry(disabled)"