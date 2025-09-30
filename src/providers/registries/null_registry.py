"""Null registry service for disabled package registry."""

import logging
from typing import List

from ...core.entities import MaliciousPackage
from ...core.interfaces import PackagesRegistryService

logger = logging.getLogger(__name__)


class NullRegistry(PackagesRegistryService):
    """Null registry service that does nothing or packages for testing."""

    def __init__(self, packages: List[MaliciousPackage] = None):
        """
        Initialize null registry.

        Args:
            packages: Optional list of packages as existing in registry for testing
        """
        self.name = "NullRegistry"
        self.base_url = (
            "https://null-registry.example.com"  # Required for test compatibility
        )
        self._packages = packages or []

    async def check_existing_packages(
        self, packages: List[MaliciousPackage]
    ) -> List[MaliciousPackage]:
        """
        Check existing packages (returns matched_packages packages if any, otherwise empty list).

        Args:
            packages: List of packages to check

        Returns:
            List of packages that exist in memory registry (or empty list)
        """
        if self._packages:
            # Find matching packages by name and ecosystem
            existing = []
            for package in packages:
                for matched_packages in self._packages:
                    if (
                        package.name.lower() == matched_packages.name.lower()
                        and package.ecosystem.lower()
                        == matched_packages.ecosystem.lower()
                    ):
                        existing.append(matched_packages)
                        break
            logger.debug(
                f"NullRegistry: Found {len(existing)} existing packages out of {len(packages)} checked"
            )
            return existing
        else:
            logger.debug(
                f"NullRegistry: Would check {len(packages)} packages (registry disabled)"
            )
            return []

    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Block packages (no-op).

        Args:
            packages: List of packages to block

        Returns:
            Empty list (no packages blocked)
        """
        logger.debug(
            f"NullRegistry: Would block {len(packages)} packages (registry disabled)"
        )
        return []

    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Unblock packages (no-op).

        Args:
            packages: List of packages to unblock

        Returns:
            Empty list (no packages unblocked)
        """
        logger.debug(
            f"NullRegistry: Would unblock {len(packages)} packages (registry disabled)"
        )
        return []

    async def block_package(self, package: MaliciousPackage) -> bool:
        """
        Block a single package (no-op).

        Args:
            package: Package to block

        Returns:
            False (no package blocked)
        """
        logger.debug(
            f"NullRegistry: Would block package {package.name} (registry disabled)"
        )
        return False

    async def search_packages(self, package_name: str, ecosystem: str) -> List[dict]:
        """
        Search for packages (returns matched packages if any, otherwise empty list).

        Args:
            package_name: Name of package to search for
            ecosystem: Package ecosystem

        Returns:
            List of matching packages (or empty list)
        """
        if self._packages:
            # Find matching packages
            matches = []
            for package in self._packages:
                if (
                    package.name.lower() == package_name.lower()
                    and package.ecosystem.lower() == ecosystem.lower()
                ):
                    # Convert to registry search result format
                    match_dict = {
                        "name": package.name,
                        "ecosystem": package.ecosystem,
                        "version": package.version,  # Individual version for CLI display
                        "versions": package.affected_versions,  # All versions for analysis
                        "registry_url": f"pkg:{ecosystem}/{package_name}",
                        "path": f"null-registry/{package.name}",
                        "size": 0,
                        "modified": "2024-09-29T06:00:00Z",
                    }
                    matches.append(match_dict)
            logger.debug(
                f"NullRegistry: Found {len(matches)} packages for {package_name} in {ecosystem}"
            )
            return matches
        else:
            logger.debug(
                f"NullRegistry: Would search for {package_name} in {ecosystem} (registry disabled)"
            )
            return []

    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """
        Check if package is blocked (no-op).

        Args:
            package: Package to check

        Returns:
            False (no packages are blocked)
        """
        logger.debug(
            f"NullRegistry: Would check if {package.name} is blocked (registry disabled)"
        )
        return False

    def get_registry_name(self) -> str:
        """
        Get registry name.

        Returns:
            Registry name
        """
        return "Null Registry"

    async def discover_repositories_by_ecosystem(self, ecosystem: str) -> List[str]:
        """
        Discover repositories (no-op).

        Args:
            ecosystem: Package ecosystem

        Returns:
            Empty list (no repositories)
        """
        logger.debug(
            f"NullRegistry: Would discover repositories for {ecosystem} (registry disabled)"
        )
        return []

    async def get_supported_ecosystems(self) -> List[str]:
        """
        Get list of ecosystems supported by this registry.

        Returns:
            List of ecosystem names that this registry can handle
        """
        return [
            "npm",
            "PyPI",
            "Maven",
            "Go",
            "NuGet",
            "RubyGems",
            "crates.io",
            "Packagist",
            "Pub",
            "Hex",
        ]

    def get_ecosystem_blocking_support(self, ecosystem: str) -> dict:
        """
        Get blocking support information for an ecosystem.

        Args:
            ecosystem: Ecosystem name

        Returns:
            Dict with support information
        """
        return {"scanning": True, "blocking": True, "pattern_quality": "full"}

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
        if self._packages:
            return f"NullRegistry(count: {len(self._packages)} packages)"
        return "NullRegistry(disabled)"
