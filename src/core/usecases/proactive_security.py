"""Proactive Security Use Case for blocking packages before analysis."""

import logging
from typing import Any, Callable, Dict, Optional

from ..entities.malicious_package import MaliciousPackage
from ..interfaces.packages_feed import PackagesFeed
from ..interfaces.packages_registry_service import PackagesRegistryService


class ProactiveSecurityUseCase:
    """Use case for proactive security operations."""

    def __init__(
        self, packages_feed: PackagesFeed, registry_service: PackagesRegistryService
    ):
        """
        Initialize the proactive security use case.

        Args:
            packages_feed: Service for fetching malicious package data
            registry_service: Service for interacting with package registry
        """
        self.packages_feed = packages_feed
        self.registry_service = registry_service
        self.logger = logging.getLogger(__name__)

    async def block_recent_malicious_packages(
        self,
        hours: int = 6,
        ecosystem: str = "npm",
        limit: Optional[int] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Proactively block recent malicious packages from OSV feed.

        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (default: npm)
            limit: Maximum number of malicious packages to process
            progress_callback: Optional callback for progress updates (message, current, total)

        Returns:
            Dictionary containing blocking results
        """
        try:
            self.logger.debug(
                f"Starting proactive blocking for {ecosystem} packages from last {hours} hours"
            )

            # Step 1: Fetch recent malicious packages
            if progress_callback:
                progress_callback(
                    "Fetching malicious packages from the Malicious packages feed...",
                    0,
                    100,
                )

            malicious_packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=limit, hours=hours
            )

            # Filter by ecosystem
            malicious_packages = [
                pkg
                for pkg in malicious_packages
                if pkg.ecosystem.lower() == ecosystem.lower()
            ]

            if not malicious_packages:
                return {
                    "success": True,
                    "total_packages": 0,
                    "blocked_packages": [],
                    "already_blocked": [],
                    "errors": [],
                    "ecosystem": ecosystem,
                    "hours": hours,
                }

            self.logger.debug(
                f"Found {len(malicious_packages)} malicious {ecosystem} packages to process"
            )

            # Step 2: Check registry health
            if progress_callback:
                progress_callback("Checking package registry health...", 10, 100)

            registry_healthy = await self.registry_service.health_check()
            if not registry_healthy:
                error_msg = "Package registry is not accessible"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "total_packages": len(malicious_packages),
                    "blocked_packages": [],
                    "already_blocked": [],
                    "errors": [error_msg],
                    "ecosystem": ecosystem,
                    "hours": hours,
                }

            # Step 3: Block packages
            blocked_packages = []
            already_blocked = []
            errors = []

            for i, package in enumerate(malicious_packages):
                try:
                    if progress_callback:
                        progress_callback(
                            f"Blocking package {package.name}...",
                            20 + int((i / len(malicious_packages)) * 70),
                            100,
                        )

                    # Check if already blocked
                    is_blocked = await self.registry_service.is_package_blocked(package)

                    if is_blocked:
                        already_blocked.append(
                            {
                                "name": package.name,
                                "ecosystem": ecosystem,
                                "message": f"Package {package.name} is already blocked",
                            }
                        )
                        self.logger.debug(f"Package {package.name} is already blocked")
                        continue

                    # Block the package
                    block_result = await self.registry_service.block_packages([package])

                    if block_result:
                        blocked_packages.append(
                            {
                                "name": package.name,
                                "ecosystem": ecosystem,
                                "version": "*",
                                "advisory_id": package.advisory_id,
                                "message": f"Successfully blocked {package.name}",
                            }
                        )
                        self.logger.debug(
                            f"Successfully blocked package: {package.name}"
                        )
                    else:
                        error_msg = f"Failed to block package: {package.name}"
                        errors.append({"package": package.name, "error": error_msg})
                        self.logger.warning(error_msg)

                except Exception as e:
                    error_msg = f"Error blocking package {package.name}: {str(e)}"
                    errors.append({"package": package.name, "error": error_msg})
                    self.logger.error(error_msg)

            if progress_callback:
                progress_callback("Proactive blocking complete", 100, 100)

            # Clean up registry connection
            await self.registry_service.close()

            success_count = len(blocked_packages)
            total_processed = len(malicious_packages)

            self.logger.info(
                f"Proactive blocking complete: {success_count}/{total_processed} packages blocked"
            )

            return {
                "success": True,
                "total_packages": total_processed,
                "blocked_packages": blocked_packages,
                "already_blocked": already_blocked,
                "errors": errors,
                "ecosystem": ecosystem,
                "hours": hours,
                "success_count": success_count,
                "already_blocked_count": len(already_blocked),
                "error_count": len(errors),
            }

        except Exception as e:
            self.logger.error(f"Error during proactive blocking: {e}")
            # Clean up registry connection on error
            try:
                await self.registry_service.close()
            except Exception as cleanup_error:
                self.logger.debug(f"Non-critical error during cleanup: {cleanup_error}")

            return {
                "success": False,
                "error": str(e),
                "total_packages": 0,
                "blocked_packages": [],
                "already_blocked": [],
                "errors": [str(e)],
                "ecosystem": ecosystem,
                "hours": hours,
            }

    async def unblock_packages_by_criteria(
        self,
        ecosystem: str = "npm",
        package_pattern: Optional[str] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Unblock packages based on criteria (useful for cleanup).

        Args:
            ecosystem: Package ecosystem (default: npm)
            package_pattern: Pattern to match package names (optional)
            dry_run: If True, only simulate the operation without making changes

        Returns:
            Dictionary containing unblocking results
        """
        try:
            self.logger.debug(
                f"Starting bulk unblock operation for {ecosystem} (dry_run={dry_run})"
            )

            # Get currently blocked packages
            blocked_packages = await self.registry_service.list_blocked_packages(
                ecosystem
            )

            if not blocked_packages:
                return {
                    "success": True,
                    "total_blocked": 0,
                    "matching_packages": [],
                    "unblocked_packages": [],
                    "errors": [],
                    "dry_run": dry_run,
                    "ecosystem": ecosystem,
                }

            # Filter by pattern if provided
            matching_packages = blocked_packages
            if package_pattern:
                import fnmatch

                matching_packages = [
                    pkg
                    for pkg in blocked_packages
                    if fnmatch.fnmatch(pkg.get("name", ""), package_pattern)
                ]

            if dry_run:
                return {
                    "success": True,
                    "total_blocked": len(blocked_packages),
                    "matching_packages": matching_packages,
                    "unblocked_packages": [],
                    "errors": [],
                    "dry_run": True,
                    "ecosystem": ecosystem,
                    "message": f"Dry run: Would unblock {len(matching_packages)} packages",
                }

            # Actually unblock packages
            unblocked_packages = []
            errors = []

            for package_info in matching_packages:
                try:
                    package_name = package_info.get("name")
                    if not package_name:
                        continue

                    temp_package = MaliciousPackage(
                        name=package_name,
                        ecosystem=ecosystem,
                        version="*",
                        package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                        advisory_id="BULK-UNBLOCK",
                        summary="Bulk unblock operation",
                        details="",
                        aliases=[],
                        affected_versions=[],
                        database_specific={},
                        published_at=None,
                        modified_at=None,
                    )

                    unblock_result = await self.registry_service.unblock_packages(
                        [temp_package]
                    )

                    if unblock_result:
                        unblocked_packages.append(
                            {
                                "name": package_name,
                                "ecosystem": ecosystem,
                                "message": f"Successfully unblocked {package_name}",
                            }
                        )
                        self.logger.debug(
                            f"Successfully unblocked package: {package_name}"
                        )
                    else:
                        error_msg = f"Failed to unblock package: {package_name}"
                        errors.append({"package": package_name, "error": error_msg})
                        self.logger.warning(error_msg)

                except Exception as e:
                    error_msg = f"Error unblocking package {package_info.get('name', 'unknown')}: {str(e)}"
                    errors.append(
                        {
                            "package": package_info.get("name", "unknown"),
                            "error": error_msg,
                        }
                    )
                    self.logger.error(error_msg)

            # Clean up registry connection
            await self.registry_service.close()

            return {
                "success": True,
                "total_blocked": len(blocked_packages),
                "matching_packages": matching_packages,
                "unblocked_packages": unblocked_packages,
                "errors": errors,
                "dry_run": False,
                "ecosystem": ecosystem,
                "unblocked_count": len(unblocked_packages),
                "error_count": len(errors),
            }

        except Exception as e:
            self.logger.error(f"Error during bulk unblock operation: {e}")
            # Clean up registry connection on error
            try:
                await self.registry_service.close()
            except Exception as cleanup_error:
                self.logger.debug(f"Non-critical error during cleanup: {cleanup_error}")

            return {
                "success": False,
                "error": str(e),
                "total_blocked": 0,
                "matching_packages": [],
                "unblocked_packages": [],
                "errors": [str(e)],
                "dry_run": dry_run,
                "ecosystem": ecosystem,
            }
