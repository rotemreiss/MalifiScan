"""Data Management Use Case for retrieving and filtering data from storage."""

from typing import Optional, Dict, List, Any
import logging
from datetime import datetime, timedelta

from ..entities.malicious_package import MaliciousPackage
from ..interfaces.storage_service import StorageService
from ..interfaces.packages_feed import PackagesFeed


class DataManagementUseCase:
    """Use case for data management operations."""
    
    def __init__(
        self,
        storage_service: StorageService,
        packages_feed: PackagesFeed
    ):
        """
        Initialize the data management use case.
        
        Args:
            storage_service: Service for storing and retrieving data
            packages_feed: Service for fetching fresh package data
        """
        self.storage_service = storage_service
        self.packages_feed = packages_feed
        self.logger = logging.getLogger(__name__)
    
    async def get_malicious_packages(
        self, 
        limit: int = 20, 
        ecosystem: Optional[str] = None, 
        hours: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get known malicious packages from storage with filtering.
        
        Args:
            limit: Maximum number of packages to return
            ecosystem: Filter by ecosystem
            hours: Filter to packages from last N hours
            
        Returns:
            Dictionary containing packages and metadata
        """
        try:
            self.logger.info(f"Retrieving malicious packages data (limit: {limit}, ecosystem: {ecosystem}, hours: {hours})")
            
            packages = await self.storage_service.get_known_malicious_packages()
            
            if not packages:
                return {
                    "success": True,
                    "total_packages": 0,
                    "filtered_packages": [],
                    "ecosystems": {},
                    "filter_info": {}
                }
            
            # Apply ecosystem filter
            if ecosystem:
                packages = [pkg for pkg in packages if pkg.ecosystem.lower() == ecosystem.lower()]
            
            # Apply time filter (last N hours)
            if hours:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                filtered_packages = []
                for pkg in packages:
                    # Check both modified_at and published_at
                    pkg_time = pkg.modified_at or pkg.published_at
                    if pkg_time and pkg_time >= cutoff_time:
                        filtered_packages.append(pkg)
                packages = filtered_packages
            
            # Create ecosystem summary
            ecosystems = {}
            for pkg in packages:
                ecosystems[pkg.ecosystem] = ecosystems.get(pkg.ecosystem, 0) + 1
            
            # Limit results
            limited_packages = packages[:limit]
            
            result = {
                "success": True,
                "total_packages": len(packages),
                "filtered_packages": limited_packages,
                "ecosystems": ecosystems,
                "filter_info": {
                    "ecosystem": ecosystem,
                    "hours": hours,
                    "limit": limit
                }
            }
            
            self.logger.info(f"Retrieved {len(limited_packages)} malicious packages (total: {len(packages)})")
            return result
            
        except Exception as e:
            self.logger.error(f"Error retrieving malicious packages data: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_packages": 0,
                "filtered_packages": [],
                "ecosystems": {},
                "filter_info": {}
            }
    
    async def get_scan_logs(self, limit: int = 20, filter_level: Optional[str] = None) -> Dict[str, Any]:
        """
        Get scan results and logs from storage.
        
        Args:
            limit: Maximum number of scan results to return
            filter_level: Filter by log level (not currently used)
            
        Returns:
            Dictionary containing scan results and metadata
        """
        try:
            self.logger.info(f"Retrieving scan logs data (limit: {limit})")
            
            scan_results = await self.storage_service.get_scan_results(limit=limit)
            
            result = {
                "success": True,
                "scan_results": scan_results,
                "total_results": len(scan_results)
            }
            
            self.logger.info(f"Retrieved {len(scan_results)} scan results")
            return result
            
        except Exception as e:
            self.logger.error(f"Error retrieving scan logs data: {e}")
            return {
                "success": False,
                "error": str(e),
                "scan_results": [],
                "total_results": 0
            }
    
    async def fetch_osv_packages(
        self, 
        ecosystem: Optional[str] = None, 
        limit: int = 100, 
        hours: int = 48
    ) -> Dict[str, Any]:
        """
        Fetch fresh malicious packages from OSV feed.
        
        Args:
            ecosystem: Filter by ecosystem
            limit: Maximum number of packages to fetch
            hours: Fetch packages modified within the last N hours
            
        Returns:
            Dictionary containing fetched packages and metadata
        """
        try:
            self.logger.info(f"Fetching OSV packages data (ecosystem: {ecosystem}, limit: {limit}, hours: {hours})")
            
            # Fetch fresh data from OSV with limit and time filter
            packages = await self.packages_feed.fetch_malicious_packages(max_packages=limit, hours=hours)
            
            # Filter by ecosystem if specified
            if ecosystem:
                packages = [pkg for pkg in packages if pkg.ecosystem.lower() == ecosystem.lower()]
            
            # Create ecosystem summary
            ecosystems = {}
            for pkg in packages:
                ecosystems[pkg.ecosystem] = ecosystems.get(pkg.ecosystem, 0) + 1
            
            result = {
                "success": True,
                "packages": packages,
                "total_packages": len(packages),
                "ecosystems": ecosystems,
                "filter_info": {
                    "ecosystem": ecosystem,
                    "limit": limit,
                    "hours": hours
                }
            }
            
            self.logger.info(f"Fetched {len(packages)} packages from OSV feed")
            return result
            
        except Exception as e:
            self.logger.error(f"Error fetching OSV packages data: {e}")
            return {
                "success": False,
                "error": str(e),
                "packages": [],
                "total_packages": 0,
                "ecosystems": {},
                "filter_info": {}
            }