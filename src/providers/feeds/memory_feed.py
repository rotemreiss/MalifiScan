"""Memory feed provider for testing with predefined malicious packages."""

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from ...core.interfaces import PackagesFeed
from ...core.entities import MaliciousPackage
from ..exceptions import FeedError


logger = logging.getLogger(__name__)


class MemoryFeed(PackagesFeed):
    """Memory feed provider that stores malicious packages in memory for testing."""
    
    def __init__(self, packages: Optional[List[MaliciousPackage]] = None):
        """
        Initialize memory feed provider.
        
        Args:
            packages: List of malicious packages to store in memory (empty list if None)
        """
        self._packages = packages or []
        self._available_ecosystems = self._extract_ecosystems()
        logger.debug(f"MemoryFeed initialized with {len(self._packages)} packages")
    
    def _extract_ecosystems(self) -> List[str]:
        """Extract unique ecosystems from stored packages."""
        ecosystems = set()
        for package in self._packages:
            if package.ecosystem:
                ecosystems.add(package.ecosystem.lower())
        return sorted(list(ecosystems))
    
    def add_package(self, package: MaliciousPackage) -> None:
        """
        Add a package to the memory feed.
        
        Args:
            package: MaliciousPackage to add
        """
        self._packages.append(package)
        # Update available ecosystems
        if package.ecosystem and package.ecosystem.lower() not in self._available_ecosystems:
            self._available_ecosystems.append(package.ecosystem.lower())
            self._available_ecosystems.sort()
        logger.debug(f"Added package {package.name} to MemoryFeed")
    
    def add_packages(self, packages: List[MaliciousPackage]) -> None:
        """
        Add multiple packages to the memory feed.
        
        Args:
            packages: List of MaliciousPackage to add
        """
        for package in packages:
            self.add_package(package)
        logger.debug(f"Added {len(packages)} packages to MemoryFeed")
    
    def clear(self) -> None:
        """Clear all packages from memory."""
        self._packages.clear()
        self._available_ecosystems.clear()
        logger.debug("MemoryFeed cleared")
    
    async def fetch_malicious_packages(
        self, 
        max_packages: Optional[int] = None, 
        hours: Optional[int] = None, 
        ecosystems: Optional[List[str]] = None
    ) -> List[MaliciousPackage]:
        """
        Fetch malicious packages from memory.
        
        Args:
            max_packages: Maximum number of packages to return (None for all)
            hours: Filter packages modified within the last N hours (None for all)
            ecosystems: List of ecosystems to filter by (None for all available ecosystems)
        
        Returns:
            List of MaliciousPackage entities matching the criteria
            
        Raises:
            FeedError: If filtering parameters are invalid
        """
        logger.debug(f"Fetching malicious packages from memory (max={max_packages}, hours={hours}, ecosystems={ecosystems})")
        
        try:
            filtered_packages = self._packages.copy()
            
            # Filter by ecosystems
            if ecosystems:
                ecosystems_lower = [eco.lower() for eco in ecosystems]
                filtered_packages = [
                    pkg for pkg in filtered_packages 
                    if pkg.ecosystem and pkg.ecosystem.lower() in ecosystems_lower
                ]
                logger.debug(f"Filtered by ecosystems {ecosystems}: {len(filtered_packages)} packages remain")
            
            # Filter by time (if packages have modified_date)
            if hours is not None:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                filtered_packages = [
                    pkg for pkg in filtered_packages
                    if not hasattr(pkg, 'modified_date') or 
                       pkg.modified_date is None or 
                       pkg.modified_date >= cutoff_time
                ]
                logger.debug(f"Filtered by time ({hours} hours): {len(filtered_packages)} packages remain")
            
            # Apply max_packages limit
            if max_packages is not None and max_packages > 0:
                filtered_packages = filtered_packages[:max_packages]
                logger.debug(f"Limited to max {max_packages} packages")
            
            logger.info(f"MemoryFeed returning {len(filtered_packages)} malicious packages")
            return filtered_packages
            
        except Exception as e:
            logger.error(f"Error fetching packages from MemoryFeed: {e}")
            raise FeedError(f"Failed to fetch packages from memory: {e}")
    
    async def get_available_ecosystems(self) -> List[str]:
        """
        Get list of available ecosystems from stored packages.
        
        Returns:
            List of ecosystem names available in memory
        """
        logger.debug(f"MemoryFeed available ecosystems: {self._available_ecosystems}")
        return self._available_ecosystems.copy()
    
    async def health_check(self) -> bool:
        """
        Check if the memory feed is healthy (always returns True).
        
        Returns:
            True (memory feed is always healthy)
        """
        logger.debug("MemoryFeed health check: OK")
        return True
    
    def get_package_count(self) -> int:
        """
        Get the total number of packages stored in memory.
        
        Returns:
            Number of packages in memory
        """
        return len(self._packages)
    
    def __str__(self) -> str:
        return f"MemoryFeed({len(self._packages)} packages, {len(self._available_ecosystems)} ecosystems)"
    
    def __repr__(self) -> str:
        return f"MemoryFeed(packages={len(self._packages)})"