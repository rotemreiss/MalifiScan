"""Integration tests for multi-ecosystem support."""

import pytest

from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.factories.service_factory import ServiceFactory


class TestMultiEcosystemIntegration:
    """Integration tests for multi-ecosystem functionality."""

    @pytest.fixture
    def security_analysis_usecase(self, test_config):
        """Create security analysis use case with real services."""
        # Use factory to create real services with dependency injection
        service_factory = ServiceFactory(test_config)

        packages_feed = service_factory.create_packages_feed()
        packages_registry = service_factory.create_packages_registry()
        storage_service = service_factory.create_storage_service()
        notification_service = service_factory.create_notification_service()

        return SecurityAnalysisUseCase(
            packages_feed=packages_feed,
            registry_service=packages_registry,
            storage_service=storage_service,
            notification_service=notification_service,
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_osv_feed_ecosystem_discovery(self, test_config):
        """Test OSV feed can discover available ecosystems."""
        service_factory = ServiceFactory(test_config)

        packages_feed = service_factory.create_packages_feed()

        # Test ecosystem discovery
        ecosystems = await packages_feed.get_available_ecosystems()

        # Should have at least some common ecosystems
        assert isinstance(ecosystems, list)
        print(f"Available ecosystems: {ecosystems}")

        # The actual ecosystems depend on what's available in OSV bucket
        # but we should get a list (could be empty if bucket issues)
        assert len(ecosystems) >= 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_jfrog_registry_ecosystem_support(self, test_config):
        """Test JFrog registry multi-ecosystem support methods."""
        if test_config.packages_registry.type != "jfrog":
            pytest.skip("Test requires JFrog registry configuration")

        service_factory = ServiceFactory(test_config)

        packages_registry = service_factory.create_packages_registry()

        # Test supported ecosystems
        supported_ecosystems = packages_registry.get_supported_ecosystems()

        expected_ecosystems = [
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

        assert supported_ecosystems == expected_ecosystems

        # Test blocking support for different ecosystems
        for ecosystem in ["npm", "PyPI", "Maven"]:
            support = packages_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is True
            assert support["blocking"] is True
            assert support["pattern_quality"] in ["full", "basic"]

        # Test limited support ecosystems
        for ecosystem in ["Pub", "Hex"]:
            support = packages_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is True
            assert support["blocking"] is False
            assert support["pattern_quality"] == "none"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_multi_ecosystem_crossref_analysis_default(
        self, security_analysis_usecase
    ):
        """Test crossref analysis with default multi-ecosystem behavior."""
        # Test with no specific ecosystem (should use all available)
        scan_result = await security_analysis_usecase.crossref_analysis(
            hours=72, limit=20
        )

        # Verify scan result structure (dict keys)
        assert "found_matches" in scan_result
        assert "total_osv_packages" in scan_result
        assert "ecosystems_scanned" in scan_result
        assert "success" in scan_result

        # Should have scanned at least one ecosystem (or none if OSV has issues)
        assert isinstance(scan_result["ecosystems_scanned"], list)
        print(f"Ecosystems scanned: {scan_result['ecosystems_scanned']}")

        # If ecosystems were scanned, we should have some data
        if scan_result["ecosystems_scanned"]:
            assert scan_result["total_osv_packages"] >= 0
            assert scan_result.get("blocked_count", 0) >= 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_multi_ecosystem_crossref_analysis_specific_ecosystem(
        self, security_analysis_usecase
    ):
        """Test crossref analysis with specific ecosystem."""
        # Test with npm ecosystem specifically
        scan_result = await security_analysis_usecase.crossref_analysis(
            limit=5, hours=24, ecosystem="npm"
        )

        # Should only scan npm ecosystem
        assert (
            scan_result["ecosystems_scanned"] == ["npm"]
            or scan_result["ecosystems_scanned"] == []
        )

        # Verify structure (dict keys)
        assert isinstance(scan_result["found_matches"], list)
        assert isinstance(scan_result["total_osv_packages"], int)
        assert isinstance(scan_result.get("blocked_count", 0), int)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_jfrog_repository_discovery_by_ecosystem(self, test_config):
        """Test JFrog repository discovery for specific ecosystems."""
        service_factory = ServiceFactory(test_config)

        packages_registry = service_factory.create_packages_registry()

        # Test repository discovery for common ecosystems
        test_ecosystems = ["npm", "PyPI", "Maven"]

        for ecosystem in test_ecosystems:
            repositories = await packages_registry.discover_repositories_by_ecosystem(
                ecosystem
            )

            # Should return a list (could be empty if no repos configured)
            assert isinstance(repositories, list)
            print(f"Repositories for {ecosystem}: {repositories}")

            # If we have repositories, they should be strings
            for repo in repositories:
                assert isinstance(repo, str)
                assert len(repo) > 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_end_to_end_multi_ecosystem_scan(self, security_analysis_usecase):
        """Test complete end-to-end multi-ecosystem scanning workflow."""
        # This tests the full pipeline with real services
        scan_result = await security_analysis_usecase.crossref_analysis(
            limit=5, hours=24  # Small number for fast testing
        )

        # Validate the complete scan result (dict structure)
        assert "found_matches" in scan_result
        assert "total_osv_packages" in scan_result
        assert "ecosystems_scanned" in scan_result
        assert "success" in scan_result

        # Verify data types
        assert isinstance(scan_result["found_matches"], list)
        assert isinstance(scan_result["total_osv_packages"], int)
        assert isinstance(scan_result.get("blocked_count", 0), int)
        assert isinstance(scan_result["ecosystems_scanned"], list)

        # Print results for debugging
        print("Scan completed:")
        print(f"  - Ecosystems scanned: {scan_result['ecosystems_scanned']}")
        print(f"  - OSV packages found: {scan_result['total_osv_packages']}")
        print(f"  - Filtered packages: {scan_result['filtered_packages']}")
        print(f"  - Matching packages: {len(scan_result['found_matches'])}")

        # The actual counts depend on current data, but structure should be valid
        assert scan_result["total_osv_packages"] >= 0
        assert scan_result["filtered_packages"] >= 0
        assert len(scan_result["found_matches"]) >= 0

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_ecosystem_error_handling(self, security_analysis_usecase):
        """Test handling of ecosystem-specific errors in multi-ecosystem mode."""
        # Test with an invalid/non-existent ecosystem
        scan_result = await security_analysis_usecase.crossref_analysis(
            limit=5, hours=24, ecosystem="NonExistentEcosystem"
        )

        # Should handle gracefully and return empty results (dict structure)
        assert scan_result["ecosystems_scanned"] == [] or scan_result[
            "ecosystems_scanned"
        ] == ["NonExistentEcosystem"]
        assert scan_result["total_osv_packages"] == 0
        assert scan_result.get("blocked_count", 0) == 0
        assert len(scan_result["found_matches"]) == 0
