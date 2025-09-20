"""Feed Management Use Case for packages feed operations."""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

from ..entities.malicious_package import MaliciousPackage
from ..interfaces.packages_feed import PackagesFeed


class FeedManagementUseCase:
    """Use case for feed management operations."""
    
    def __init__(self, packages_feed: PackagesFeed):
        """
        Initialize the feed management use case.
        
        Args:
            packages_feed: Service for fetching malicious package data
        """
        self.packages_feed = packages_feed
        self.logger = logging.getLogger(__name__)
    
    async def fetch_recent_packages(
        self, 
        ecosystem: Optional[str] = None, 
        limit: int = 100, 
        hours: int = 48
    ) -> Dict[str, Any]:
        """
        Fetch recent malicious packages from the feed.
        
        Args:
            ecosystem: Filter by ecosystem (npm, pypi, etc.)
            limit: Maximum number of packages to fetch
            hours: Fetch packages modified within the last N hours
            
        Returns:
            Dictionary containing fetched packages and metadata
        """
        try:
            self.logger.debug(f"Fetching recent malicious packages: ecosystem={ecosystem}, limit={limit}, hours={hours}")
            
            # Fetch packages from the feed
            packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=limit,
                hours=hours
            )
            
            # Filter by ecosystem if specified
            if ecosystem:
                packages = [pkg for pkg in packages if pkg.ecosystem.lower() == ecosystem.lower()]
            
            # Group packages by ecosystem for summary
            ecosystem_counts = {}
            for pkg in packages:
                eco = pkg.ecosystem.lower()
                ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1
            
            return {
                "success": True,
                "packages": packages,
                "total_count": len(packages),
                "ecosystem_filter": ecosystem,
                "hours_filter": hours,
                "limit": limit,
                "ecosystem_counts": ecosystem_counts,
                "fetch_time": datetime.now(timezone.utc)
            }
            
        except Exception as e:
            self.logger.error(f"Error fetching recent packages: {e}")
            return {
                "success": False,
                "error": str(e),
                "packages": [],
                "total_count": 0,
                "ecosystem_filter": ecosystem,
                "hours_filter": hours,
                "limit": limit,
                "ecosystem_counts": {},
                "fetch_time": datetime.now(timezone.utc)
            }
    
    async def get_feed_health(self) -> Dict[str, Any]:
        """
        Check feed health and connectivity.
        
        Returns:
            Dictionary containing feed health status
        """
        try:
            self.logger.debug("Checking packages feed health")
            
            # Try to fetch a small sample to test connectivity
            test_packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=1,
                hours=24
            )
            
            is_healthy = test_packages is not None
            
            return {
                "success": True,
                "healthy": is_healthy,
                "feed_name": getattr(self.packages_feed, 'name', 'Package Feed'),
                "test_fetch_count": len(test_packages) if test_packages else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error checking feed health: {e}")
            return {
                "success": False,
                "error": str(e),
                "healthy": False,
                "feed_name": getattr(self.packages_feed, 'name', 'Package Feed'),
                "test_fetch_count": 0
            }
    
    async def get_package_details(self, package_name: str, ecosystem: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific malicious package.
        
        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem
            
        Returns:
            Dictionary containing package details
        """
        try:
            self.logger.debug(f"Getting details for package: {package_name} ({ecosystem})")
            
            # Fetch recent packages and filter for the specific one
            packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=1000,  # Cast a wide net
                hours=24 * 30  # Look back 30 days
            )
            
            # Find matching packages
            matching_packages = [
                pkg for pkg in packages 
                if pkg.name.lower() == package_name.lower() and 
                   pkg.ecosystem.lower() == ecosystem.lower()
            ]
            
            if not matching_packages:
                return {
                    "success": True,
                    "found": False,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "packages": []
                }
            
            return {
                "success": True,
                "found": True,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "packages": matching_packages,
                "count": len(matching_packages)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting package details for {package_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "found": False,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "packages": []
            }