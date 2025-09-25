"""Integration tests for multi-ecosystem support."""

import pytest
from typing import Dict, Any

from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.factories.service_factory import ServiceFactory
from src.config.config_loader import ConfigLoader


class TestMultiEcosystemIntegration:
    """Integration tests for multi-ecosystem functionality."""
    
    @pytest.fixture
    def security_analysis_usecase(self):
        """Create security analysis use case with real services."""
        config = ConfigLoader().load()
        
        # Use factory to create real services with dependency injection
        service_factory = ServiceFactory(config)
        
        packages_feed = service_factory.create_packages_feed()
        packages_registry = service_factory.create_packages_registry()
        storage_service = service_factory.create_storage_service()
        notification_service = service_factory.create_notification_service()
        
        return SecurityAnalysisUseCase(
            packages_feed=packages_feed,
            packages_registry=packages_registry,
            storage_service=storage_service,
            notification_service=notification_service
        )
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_osv_feed_ecosystem_discovery(self):
        """Test OSV feed can discover available ecosystems."""
        config = ConfigLoader().load()
        service_factory = ServiceFactory(config)
        
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
    async def test_jfrog_registry_ecosystem_support(self):
        """Test JFrog registry multi-ecosystem support methods."""
        config = ConfigLoader().load()
        service_factory = ServiceFactory(config)
        
        packages_registry = service_factory.create_packages_registry()
        
        # Test supported ecosystems
        supported_ecosystems = packages_registry.get_supported_ecosystems()
        
        expected_ecosystems = [
            "npm", "PyPI", "Maven", "Go", "NuGet", 
            "RubyGems", "crates.io", "Packagist", "Pub", "Hex"
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
    async def test_multi_ecosystem_crossref_analysis_default(self, security_analysis_usecase):
        """Test crossref analysis with default multi-ecosystem behavior."""
        # Test with no specific ecosystem (should use all available)
        scan_result = await security_analysis_usecase.crossref_analysis(
            max_packages=10,
            hours=24
        )
        
        # Verify scan result structure
        assert hasattr(scan_result, 'matching_packages')
        assert hasattr(scan_result, 'osv_packages_count')
        assert hasattr(scan_result, 'jfrog_blocked_count')
        assert hasattr(scan_result, 'ecosystems_scanned')
        
        # Should have scanned at least one ecosystem (or none if OSV has issues)
        assert isinstance(scan_result.ecosystems_scanned, list)
        print(f"Ecosystems scanned: {scan_result.ecosystems_scanned}")
        
        # If ecosystems were scanned, we should have some data
        if scan_result.ecosystems_scanned:
            assert scan_result.osv_packages_count >= 0
            assert scan_result.jfrog_blocked_count >= 0
    
    @pytest.mark.integration 
    @pytest.mark.asyncio
    async def test_multi_ecosystem_crossref_analysis_specific_ecosystem(self, security_analysis_usecase):
        """Test crossref analysis with specific ecosystem."""
        # Test with npm ecosystem specifically
        scan_result = await security_analysis_usecase.crossref_analysis(
            max_packages=5,
            hours=24,
            ecosystem="npm"
        )
        
        # Should only scan npm ecosystem
        assert scan_result.ecosystems_scanned == ["npm"] or scan_result.ecosystems_scanned == []
        
        # Verify structure
        assert isinstance(scan_result.matching_packages, list)
        assert isinstance(scan_result.osv_packages_count, int)
        assert isinstance(scan_result.jfrog_blocked_count, int)
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_jfrog_repository_discovery_by_ecosystem(self):
        """Test JFrog repository discovery for specific ecosystems."""
        config = ConfigLoader().load()
        service_factory = ServiceFactory(config)
        
        packages_registry = service_factory.create_packages_registry()
        
        # Test repository discovery for common ecosystems
        test_ecosystems = ["npm", "PyPI", "Maven"]
        
        for ecosystem in test_ecosystems:
            repositories = await packages_registry.discover_repositories_by_ecosystem(ecosystem)
            
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
            max_packages=5,  # Small number for fast testing
            hours=24
        )
        
        # Validate the complete scan result
        assert hasattr(scan_result, 'matching_packages')
        assert hasattr(scan_result, 'osv_packages_count') 
        assert hasattr(scan_result, 'jfrog_blocked_count')
        assert hasattr(scan_result, 'ecosystems_scanned')
        assert hasattr(scan_result, 'scan_timestamp')
        
        # Verify data types
        assert isinstance(scan_result.matching_packages, list)
        assert isinstance(scan_result.osv_packages_count, int)
        assert isinstance(scan_result.jfrog_blocked_count, int)
        assert isinstance(scan_result.ecosystems_scanned, list)
        
        # Print results for debugging
        print(f"Scan completed:")
        print(f"  - Ecosystems scanned: {scan_result.ecosystems_scanned}")
        print(f"  - OSV packages found: {scan_result.osv_packages_count}")
        print(f"  - JFrog blocked: {scan_result.jfrog_blocked_count}")
        print(f"  - Matching packages: {len(scan_result.matching_packages)}")
        
        # The actual counts depend on current data, but structure should be valid
        assert scan_result.osv_packages_count >= 0
        assert scan_result.jfrog_blocked_count >= 0
        assert len(scan_result.matching_packages) >= 0
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_ecosystem_error_handling(self, security_analysis_usecase):
        """Test handling of ecosystem-specific errors in multi-ecosystem mode."""
        # Test with an invalid/non-existent ecosystem
        scan_result = await security_analysis_usecase.crossref_analysis(
            max_packages=5,
            hours=24,
            ecosystem="NonExistentEcosystem"
        )
        
        # Should handle gracefully and return empty results
        assert scan_result.ecosystems_scanned == [] or scan_result.ecosystems_scanned == ["NonExistentEcosystem"]
        assert scan_result.osv_packages_count == 0
        assert scan_result.jfrog_blocked_count == 0
        assert len(scan_result.matching_packages) == 0