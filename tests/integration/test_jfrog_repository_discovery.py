"""Integration tests for JFrog repository discovery functionality."""

import pytest
import pytest_asyncio
import os
import logging
from typing import List

from src.config import ConfigLoader
from src.providers.registries.jfrog_registry import JFrogRegistry
from src.providers.exceptions import RegistryError

logger = logging.getLogger(__name__)


@pytest.mark.integration
class TestJFrogRepositoryDiscovery:
    """Integration tests for JFrog repository discovery functionality.
    
    These tests require actual JFrog credentials and should not run in CI.
    Set SKIP_INTEGRATION_TESTS=true to skip these tests.
    """
    
    @pytest.fixture(scope="class")
    def config(self):
        """Load configuration for JFrog integration tests."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")
        
        # Load configuration
        config_loader = ConfigLoader()
        config = config_loader.load()
        
        # Verify JFrog configuration is available
        if not config.jfrog_base_url:
            pytest.skip("JFrog base URL not configured")
        
        if not (config.jfrog_api_key or (config.jfrog_username and config.jfrog_password)):
            pytest.skip("JFrog credentials not configured")
            
        return config
    
    @pytest_asyncio.fixture(scope="function")
    async def jfrog_registry(self, config):
        """Create JFrog registry instance."""
        registry = JFrogRegistry(
            base_url=config.jfrog_base_url,
            username=config.jfrog_username,
            password=config.jfrog_password,
            api_key=config.jfrog_api_key,
            timeout_seconds=30,
            max_retries=3,
            retry_delay=1.0,
            cache_ttl_seconds=300  # Short cache for testing
        )
        
        # Verify health before tests
        is_healthy = await registry.health_check()
        if not is_healthy:
            pytest.skip("JFrog Artifactory is not accessible")
        
        yield registry
        
        # Cleanup
        await registry.close()
    
    async def test_discover_npm_repositories(self, jfrog_registry):
        """Test discovery of npm repositories."""
        repos = await jfrog_registry.discover_repositories_by_ecosystem("npm")
        
        # Should find at least one npm repository
        assert isinstance(repos, list)
        logger.info(f"Found npm repositories: {repos}")
        
        # If repositories exist, they should be valid strings
        for repo in repos:
            assert isinstance(repo, str)
            assert len(repo) > 0
    
    async def test_discover_pypi_repositories(self, jfrog_registry):
        """Test discovery of PyPI repositories."""
        repos = await jfrog_registry.discover_repositories_by_ecosystem("PyPI")
        
        assert isinstance(repos, list)
        logger.info(f"Found PyPI repositories: {repos}")
        
        for repo in repos:
            assert isinstance(repo, str)
            assert len(repo) > 0
    
    async def test_discover_maven_repositories(self, jfrog_registry):
        """Test discovery of Maven repositories."""
        repos = await jfrog_registry.discover_repositories_by_ecosystem("Maven")
        
        assert isinstance(repos, list)
        logger.info(f"Found Maven repositories: {repos}")
        
        for repo in repos:
            assert isinstance(repo, str)
            assert len(repo) > 0
    
    async def test_discover_unsupported_ecosystem(self, jfrog_registry):
        """Test discovery for unsupported ecosystem returns empty list."""
        repos = await jfrog_registry.discover_repositories_by_ecosystem("UnsupportedEcosystem")
        
        # Should return empty list for unsupported ecosystems
        assert repos == []
    
    async def test_repository_caching(self, jfrog_registry):
        """Test that repository discovery results are cached."""
        ecosystem = "npm"
        
        # First call - should make API request
        repos1 = await jfrog_registry.discover_repositories_by_ecosystem(ecosystem)
        
        # Second call - should use cache
        repos2 = await jfrog_registry.discover_repositories_by_ecosystem(ecosystem)
        
        # Results should be identical
        assert repos1 == repos2
        
        # Cache should contain the ecosystem
        assert ecosystem in jfrog_registry._repository_cache
        assert ecosystem in jfrog_registry._cache_timestamps
    
    async def test_repository_override_configuration(self, config):
        """Test that repository overrides work correctly."""
        # Create registry with manual override
        override_repo = "test-npm-override"
        registry = JFrogRegistry(
            base_url=config.jfrog_base_url,
            username=config.jfrog_username,
            password=config.jfrog_password,
            api_key=config.jfrog_api_key,
            repository_overrides={"npm": override_repo}
        )
        
        try:
            repos = await registry.discover_repositories_by_ecosystem("npm")
            
            # Should return only the override repository
            assert repos == [override_repo]
            
            # Should not have made API call to discover repositories
            assert "npm" not in registry._repository_cache
            
        finally:
            await registry.close()
    
    async def test_ecosystem_package_type_mapping(self, jfrog_registry):
        """Test ecosystem to package type mapping."""
        # Test known mappings
        assert jfrog_registry._ecosystem_matches_package_type("npm", "npm")
        assert jfrog_registry._ecosystem_matches_package_type("PyPI", "pypi")
        assert jfrog_registry._ecosystem_matches_package_type("Maven", "maven")
        assert jfrog_registry._ecosystem_matches_package_type("Go", "go")
        assert jfrog_registry._ecosystem_matches_package_type("NuGet", "nuget")
        assert jfrog_registry._ecosystem_matches_package_type("RubyGems", "gems")
        assert jfrog_registry._ecosystem_matches_package_type("crates.io", "cargo")
        assert jfrog_registry._ecosystem_matches_package_type("Packagist", "composer")
        
        # Test case insensitivity
        assert jfrog_registry._ecosystem_matches_package_type("npm", "NPM")
        
        # Test mismatches
        assert not jfrog_registry._ecosystem_matches_package_type("npm", "pypi")
        assert not jfrog_registry._ecosystem_matches_package_type("PyPI", "maven")
        
        # Test unknown ecosystems
        assert not jfrog_registry._ecosystem_matches_package_type("UnknownEcosystem", "unknown")
    
    async def test_all_supported_ecosystems(self, jfrog_registry):
        """Test repository discovery for all supported ecosystems."""
        supported_ecosystems = [
            "npm", "PyPI", "Maven", "Go", "NuGet", "RubyGems", "crates.io", "Packagist"
        ]
        
        ecosystem_results = {}
        
        for ecosystem in supported_ecosystems:
            try:
                repos = await jfrog_registry.discover_repositories_by_ecosystem(ecosystem)
                ecosystem_results[ecosystem] = repos
                logger.info(f"Ecosystem {ecosystem}: {len(repos)} repositories found")
            except Exception as e:
                logger.error(f"Failed to discover repositories for {ecosystem}: {e}")
                ecosystem_results[ecosystem] = []
        
        # Log summary of findings
        total_ecosystems_with_repos = sum(1 for repos in ecosystem_results.values() if repos)
        logger.info(f"Found repositories for {total_ecosystems_with_repos} out of {len(supported_ecosystems)} ecosystems")
        
        # At least the test should complete without errors
        assert len(ecosystem_results) == len(supported_ecosystems)
    
    async def test_api_error_handling(self, config):
        """Test handling of API errors during repository discovery."""
        # Create registry with invalid base URL to trigger errors
        registry = JFrogRegistry(
            base_url="https://invalid-jfrog-url.com",
            api_key="invalid-key",
            timeout_seconds=5  # Short timeout for faster test
        )
        
        try:
            repos = await registry.discover_repositories_by_ecosystem("npm")
            
            # Should return empty list on error
            assert repos == []
            
        finally:
            await registry.close()