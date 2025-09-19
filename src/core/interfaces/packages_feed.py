"""Packages feed interface."""

from abc import ABC, abstractmethod
from typing import List, Optional

from src.core.entities import MaliciousPackage


class PackagesFeed(ABC):
    """Abstract interface for malicious packages feed providers."""
    
    @abstractmethod
    async def fetch_malicious_packages(self, max_packages: Optional[int] = None, hours: Optional[int] = None) -> List[MaliciousPackage]:
        """
        Fetch list of malicious packages from the feed.
        
        Args:
            max_packages: Maximum number of packages to fetch (None for all)
            hours: Fetch packages modified within the last N hours (None for all time)
        
        Returns:
            List of MaliciousPackage entities
            
        Raises:
            FeedError: If the feed cannot be accessed or parsed
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the feed service is healthy and accessible.
        
        Returns:
            True if service is healthy, False otherwise
        """
        pass