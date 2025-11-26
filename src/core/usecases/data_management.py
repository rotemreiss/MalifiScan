"""Data Management Use Case for retrieving and filtering data from storage."""

import logging
from typing import Any, Dict, Optional

from ..interfaces.packages_feed import PackagesFeed
from ..interfaces.storage_service import StorageService


class DataManagementUseCase:
    """Use case for data management operations."""

    def __init__(self, storage_service: StorageService, packages_feed: PackagesFeed):
        """
        Initialize the data management use case.

        Args:
            storage_service: Service for storing and retrieving data
            packages_feed: Service for fetching fresh package data
        """
        self.storage_service = storage_service
        self.packages_feed = packages_feed
        self.logger = logging.getLogger(__name__)

    async def fetch_osv_packages(
        self,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None,
        hours: int = 48,
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
            self.logger.info(
                f"Fetching OSV packages data (ecosystem: {ecosystem}, limit: {limit}, hours: {hours})"
            )

            # Build ecosystems list for feed
            ecosystems = [ecosystem] if ecosystem else None

            # Fetch fresh data from OSV with limit, time filter, and ecosystem filter
            packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=limit, hours=hours, ecosystems=ecosystems
            )

            # Get cache statistics
            cache_stats = self.packages_feed.get_cache_stats()

            # Create ecosystem summary
            ecosystems = {}
            for pkg in packages:
                ecosystems[pkg.ecosystem] = ecosystems.get(pkg.ecosystem, 0) + 1

            result = {
                "success": True,
                "packages": packages,
                "total_packages": len(packages),
                "ecosystems": ecosystems,
                "cache_stats": cache_stats,
                "filter_info": {"ecosystem": ecosystem, "limit": limit, "hours": hours},
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
                "filter_info": {},
            }
