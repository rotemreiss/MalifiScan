"""Package Management Use Case for blocking and searching packages in registry."""

import logging
from datetime import datetime
from typing import Any, Dict

from ..entities.malicious_package import MaliciousPackage
from ..interfaces.packages_registry_service import PackagesRegistryService
from ..interfaces.storage_service import StorageService


class PackageManagementUseCase:
    """Use case for package management operations."""

    def __init__(
        self, registry_service: PackagesRegistryService, storage_service: StorageService
    ):
        """
        Initialize the package management use case.

        Args:
            registry_service: Service for interacting with package registry
            storage_service: Service for storing package data
        """
        self.registry_service = registry_service
        self.storage_service = storage_service
        self.logger = logging.getLogger(__name__)

    async def search_package(
        self, package_name: str, ecosystem: str = "npm"
    ) -> Dict[str, Any]:
        """
        Search for a package in registry and return structured results.

        Args:
            package_name: Name of the package to search for
            ecosystem: Package ecosystem (default: npm)

        Returns:
            Dictionary containing search results and metadata
        """
        try:
            self.logger.debug(f"Searching for package: {package_name} ({ecosystem})")

            # Check registry health
            health = await self.registry_service.health_check()
            if not health:
                self.logger.warning("JFrog Artifactory is not accessible")
                return {
                    "success": False,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "registry_healthy": False,
                    "search_results": [],
                    "is_blocked": False,
                    "error": "Registry not accessible",
                }

            # Search for packages
            search_results = await self.registry_service.search_packages(
                package_name, ecosystem
            )

            # Create a test package to check if it's blocked
            test_package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version=None,
                package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                advisory_id="CLI-SEARCH",
                summary="CLI search test package",
                details="",
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=None,
                modified_at=None,
            )

            # Check if package is blocked
            is_blocked = await self.registry_service.is_package_blocked(test_package)

            # Clean up registry connection
            await self.registry_service.close()

            result = {
                "success": True,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "registry_healthy": health,
                "search_results": search_results,
                "is_blocked": is_blocked,
                "results_count": len(search_results),
            }

            self.logger.debug(
                f"Package search completed: {len(search_results)} results found, blocked: {is_blocked}"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error searching for package {package_name}: {e}")
            # Clean up registry connection on error
            if self.registry_service:
                try:
                    await self.registry_service.close()
                except Exception as cleanup_error:
                    self.logger.debug(
                        f"Non-critical error during cleanup: {cleanup_error}"
                    )

            return {
                "success": False,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "registry_healthy": False,
                "search_results": [],
                "is_blocked": False,
                "error": str(e),
            }

    async def block_package(
        self, package_name: str, ecosystem: str = "npm", version: str = "*"
    ) -> Dict[str, Any]:
        """
        Block a package in registry.

        Args:
            package_name: Name of the package to block
            ecosystem: Package ecosystem (default: npm)
            version: Package version (default: *)

        Returns:
            Dictionary containing block operation results
        """
        try:
            self.logger.debug(
                f"Blocking package: {package_name} ({ecosystem}) version {version}"
            )

            # Create package object
            package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version=version,
                package_url=f"pkg:{ecosystem.lower()}/{package_name}@{version}",
                advisory_id="CLI-MANUAL-BLOCK",
                summary=f"Manually blocked via CLI at {datetime.now()}",
                details="Package blocked using CLI testing tool",
                aliases=[],
                affected_versions=[version] if version != "*" else [],
                database_specific={},
                published_at=None,
                modified_at=None,
            )

            # Block the package
            success = await self.registry_service.block_package(package)

            if success:
                self.logger.debug(f"Successfully blocked {package_name}")

                # Also store in our database for tracking
                await self.storage_service.store_malicious_packages([package])

                return {
                    "success": True,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "message": f"Successfully blocked {package_name}",
                }
            else:
                self.logger.warning(f"Failed to block {package_name}")
                return {
                    "success": False,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "error": f"Failed to block {package_name}",
                }

        except Exception as e:
            self.logger.error(f"Error blocking package {package_name}: {e}")
            return {
                "success": False,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "error": str(e),
            }
