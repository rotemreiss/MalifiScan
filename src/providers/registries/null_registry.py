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
    
    async def health_check(self) -> bool:
        """
        Check service health.
        
        Returns:
            True (always healthy)
        """
        return True
    
    def __str__(self) -> str:
        return "NullRegistry(disabled)"