"""Unit tests for NullRegistry provider."""

import pytest

from src.core.entities import MaliciousPackage
from src.providers.registries.null_registry import NullRegistry


class TestNullRegistry:
    """Test the NullRegistry provider."""

    def test_null_registry_initialization_disabled(self):
        """Test NullRegistry initialization without simulation (disabled mode)."""
        registry = NullRegistry()

        assert registry.name == "NullRegistry"
        assert str(registry) == "NullRegistry(disabled)"

    def test_null_registry_initialization_with_simulation(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test NullRegistry initialization with simulated packages."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        registry = NullRegistry(packages=packages)

        assert registry.name == "NullRegistry"
        assert str(registry) == "NullRegistry(count: 2 packages)"

    @pytest.mark.asyncio
    async def test_check_existing_packages_disabled(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test checking existing packages when disabled (no simulation)."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        registry = NullRegistry()

        existing = await registry.check_existing_packages(packages)

        assert len(existing) == 0

    @pytest.mark.asyncio
    async def test_check_existing_packages_with_simulation(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test checking existing packages with simulation."""
        packages = [sample_malicious_package, sample_npm_malicious_package]

        # Simulate only first package exists in registry
        simulated = [sample_malicious_package]
        registry = NullRegistry(packages=simulated)

        # Check all packages (should find first one)
        existing = await registry.check_existing_packages(packages)

        assert len(existing) == 1
        assert (
            existing[0].name == "test-pypi-pkg"
        )  # sample_malicious_package is the PyPI package

        # Simulate only first package exists in registry
        simulated = [sample_malicious_package]
        registry = NullRegistry(packages=simulated)

        # Check all packages (should find first one)
        existing = await registry.check_existing_packages(packages)

        assert len(existing) == 1
        assert existing[0].name == "test-pypi-pkg"

    @pytest.mark.asyncio
    async def test_check_existing_packages_case_insensitive(self):
        """Test that package matching is case insensitive."""
        # Create simulated package with different case
        simulated = [
            MaliciousPackage(
                name="TEST-PACKAGE-A",  # Upper case name
                version="1.0.0",
                ecosystem="NPM",  # Upper case ecosystem
                package_url="pkg:npm/test-package-a@1.0.0",
                advisory_id="TEST-001",
                summary="Test case insensitive package",
                details="Test vulnerability details",
                aliases=["CVE-2024-TEST-CASE"],
                affected_versions=["1.0.0"],
                database_specific={"severity": "HIGH"},
                published_at=None,
                modified_at=None,
            )
        ]

        registry = NullRegistry(packages=simulated)

        # Look for lower case package
        lookup_packages = [
            MaliciousPackage(
                name="test-package-a",  # Lower case name
                version="1.0.0",
                ecosystem="npm",  # Lower case ecosystem
                package_url="pkg:npm/test-package-a@1.0.0",
                advisory_id="TEST-001",
                summary="Test case insensitive package lookup",
                details="Test vulnerability details",
                aliases=["CVE-2024-TEST-CASE"],
                affected_versions=["1.0.0"],
                database_specific={"severity": "HIGH"},
                published_at=None,
                modified_at=None,
            )
        ]

        existing = await registry.check_existing_packages(lookup_packages)

        assert len(existing) == 1
        assert existing[0].name == "TEST-PACKAGE-A"  # Returns the simulated package

    @pytest.mark.asyncio
    async def test_search_packages_disabled(self):
        """Test searching packages when disabled (no simulation)."""
        registry = NullRegistry()

        results = await registry.search_packages("test-package", "npm")

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_packages_with_simulation(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test searching packages with simulation."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        registry = NullRegistry(packages=packages)

        # Search for existing package
        results = await registry.search_packages("test-critical-npm", "npm")

        assert len(results) == 1
        assert results[0]["name"] == "test-critical-npm"
        assert results[0]["ecosystem"] == "npm"
        assert results[0]["versions"] == [
            "1.0.0",
            "1.1.0",
        ]  # From sample_npm_malicious_package affected_versions
        assert results[0]["registry_url"] == "pkg:npm/test-critical-npm"

        # Search for non-existing package
        results = await registry.search_packages("non-existent", "npm")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_block_operations_disabled(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test blocking operations when disabled."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        registry = NullRegistry()

        # Test block_packages
        blocked = await registry.block_packages(packages)
        assert len(blocked) == 0

        # Test block_package
        result = await registry.block_package(sample_malicious_package)
        assert result is False

        # Test unblock_packages
        unblocked = await registry.unblock_packages(packages)
        assert len(unblocked) == 0

        # Test is_package_blocked
        is_blocked = await registry.is_package_blocked(sample_malicious_package)
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_other_operations_disabled(self):
        """Test other operations when disabled."""
        registry = NullRegistry()

        # Test discover_repositories_by_ecosystem
        repos = await registry.discover_repositories_by_ecosystem("npm")
        assert len(repos) == 0

        # Test close (should not raise)
        await registry.close()

        # Test health_check
        health = await registry.health_check()
        assert health is True

        # Test get_registry_name
        name = registry.get_registry_name()
        assert name == "Null Registry"

    @pytest.mark.asyncio
    async def test_ecosystem_filtering(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test that ecosystem filtering works correctly."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        registry = NullRegistry(packages=packages)

        # Search for npm package in npm ecosystem
        # sample_npm_malicious_package is "test-critical-npm"
        results = await registry.search_packages("test-critical-npm", "npm")
        assert len(results) == 1
        assert results[0]["name"] == "test-critical-npm"

        # Search for npm package in wrong ecosystem
        results = await registry.search_packages("test-critical-npm", "pypi")
        assert len(results) == 0

        # Search for pypi package in pypi ecosystem
        # sample_malicious_package is "test-pypi-pkg" in PyPI ecosystem
        results = await registry.search_packages("test-pypi-pkg", "PyPI")
        assert len(results) == 1
        assert results[0]["name"] == "test-pypi-pkg"
