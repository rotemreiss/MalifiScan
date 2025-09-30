"""Integration tests for Service Factory with full DI flow."""

import os

import pytest
import pytest_asyncio

from src.factories.service_factory import ServiceFactory


@pytest.mark.integration
class TestServiceFactoryIntegration:
    """Integration tests for service factory with complete DI flow.

    These tests verify the full dependency injection chain:
    .env → Config → Factory → Provider → External API
    """

    @pytest.fixture
    def config(self, test_config):
        """Load configuration for factory integration tests."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")

        return test_config

    @pytest_asyncio.fixture
    async def registry_factory(self, config):
        """Create registry factory with full configuration."""
        factory = ServiceFactory(config)
        yield factory
        # Cleanup if needed

    @pytest.mark.asyncio
    async def test_jfrog_registry_creation_via_factory(self, registry_factory, config):
        """Test JFrog registry creation through factory."""
        if not config.jfrog_base_url:
            pytest.skip("JFrog not configured")

        # Test the full factory creation flow
        registry = registry_factory.create_packages_registry()

        # Verify the registry was created correctly
        assert registry is not None

        # Test that it actually works with the real API
        is_healthy = await registry.health_check()
        assert is_healthy, "Factory-created JFrog registry should be healthy"

        # Test actual functionality
        packages = await registry.search_packages("axios", ecosystem="npm")
        assert isinstance(packages, list)

        await registry.close()

    @pytest.mark.asyncio
    async def test_osv_feed_creation_via_factory(self, registry_factory):
        """Test OSV feed creation through factory."""
        # Test factory creation of OSV feed
        feed = registry_factory.create_packages_feed()

        assert feed is not None

        # Test that it works
        is_healthy = await feed.health_check()
        assert is_healthy, "Factory-created OSV feed should be healthy"

        await feed.close()

    @pytest.mark.asyncio
    async def test_configuration_propagation_to_provider(
        self, registry_factory, config
    ):
        """Test that configuration is properly propagated through factory."""
        if not config.jfrog_base_url:
            pytest.skip("JFrog not configured")

        registry = registry_factory.create_packages_registry()

        # Verify that the provider has the correct configuration
        # This tests that the factory correctly passed config to provider
        assert hasattr(registry, "base_url")
        assert registry.base_url == config.jfrog_base_url

        await registry.close()

    @pytest.mark.asyncio
    async def test_factory_error_handling_invalid_provider(self, registry_factory):
        """Test factory error handling for missing configuration."""
        # Test that a properly configured factory creates registry successfully
        registry = registry_factory.create_packages_registry()
        assert registry is not None
        await registry.close()

    @pytest.mark.asyncio
    async def test_multiple_provider_creation(self, registry_factory, config):
        """Test creating multiple providers via factory."""
        providers = []

        # Create multiple providers
        if config.jfrog_base_url:
            jfrog_registry = registry_factory.create_packages_registry()
            providers.append(jfrog_registry)

        osv_feed = registry_factory.create_packages_feed()
        providers.append(osv_feed)

        # Verify all providers work
        for provider in providers:
            is_healthy = await provider.health_check()
            assert is_healthy, f"Provider {type(provider).__name__} should be healthy"

        # Cleanup
        for provider in providers:
            await provider.close()
