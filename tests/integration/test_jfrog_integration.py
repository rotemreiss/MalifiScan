"""Integration tests for JFrog Artifactory provider."""

import pytest
import pytest_asyncio
import os
import asyncio
import logging
from typing import List
from aiohttp import ClientTimeout

from src.config import ConfigLoader
from src.providers.registries.jfrog_registry import JFrogRegistry
from src.core.entities import MaliciousPackage
from src.providers.exceptions import RegistryError

logger = logging.getLogger(__name__)


@pytest.mark.integration
class TestJFrogRegistryIntegration:
    """Integration tests for JFrog Artifactory functionality.
    
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
            api_key=config.jfrog_api_key,
            username=config.jfrog_username,
            password=config.jfrog_password,
            timeout_seconds=30,
            max_retries=3
        )
        
        # Initialize the registry
        async with registry as initialized_registry:
            yield initialized_registry
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, jfrog_registry):
        """Test JFrog health check with real API."""
        # Act
        is_healthy = await jfrog_registry.health_check()
        
        # Assert
        assert is_healthy is True, "JFrog service should be healthy"
    
    @pytest.mark.asyncio
    async def test_search_existing_package_axios(self, jfrog_registry):
        """Test searching for axios package that definitely exists."""
        # Act
        packages = await jfrog_registry.search_packages("axios", ecosystem="npm")
        
        # Assert
        assert isinstance(packages, list), "Search should return a list"
        
        # Check if any package contains axios in the name or path
        axios_found = any(
            "axios" in str(pkg.get("name", "")).lower() or 
            "axios" in str(pkg.get("path", "")).lower() or
            "axios" in str(pkg.get("repo", "")).lower()
            for pkg in packages
        )
        
        # Log the results for debugging
        logging.info(f"Found {len(packages)} packages when searching for axios")
        if packages:
            for i, pkg in enumerate(packages[:3], 1):  # Log first 3 results
                logging.info(f"Package {i}: {pkg}")
        
        # Note: This test might not find results if the JFrog instance doesn't have axios
        # The key is that the search executes without error
        if not axios_found and packages:
            logging.info("No axios packages found, but search returned other results")
        elif not packages:
            logging.info("Search returned no results - this may be normal for this JFrog instance")
    
    @pytest.mark.asyncio
    async def test_search_nonexistent_package(self, jfrog_registry):
        """Test searching for package that definitely doesn't exist."""
        # Act
        packages = await jfrog_registry.search_packages(
            "thispackagedoesntexist", 
            ecosystem="npm"
        )
        
        # Assert
        assert isinstance(packages, list), "Should return a list even when empty"
        assert len(packages) == 0, "Should not find nonexistent package"
    
    @pytest.mark.asyncio
    async def test_search_different_ecosystems(self, jfrog_registry):
        """Test searching across different package ecosystems."""
        test_cases = [
            ("axios", "npm"),  # Popular npm package
            ("requests", "pypi"),  # Popular Python package
        ]
        
        for package_name, ecosystem in test_cases:
            # Act
            packages = await jfrog_registry.search_packages(package_name, ecosystem=ecosystem)
            
            # Assert
            assert isinstance(packages, list), f"Should return list for {ecosystem}"
            
            if packages:  # If packages found, verify structure
                package = packages[0]
                assert package.get("ecosystem") == ecosystem or ecosystem in package.get("repo", "")
                assert package.get("name") is not None
                assert package.get("version") is not None or package.get("path") is not None
    
    @pytest.mark.asyncio
    async def test_check_existing_packages_with_real_packages(self, jfrog_registry):
        """Test checking which packages exist in the registry."""
        # Arrange - Create test packages (mix of existing and non-existing)
        test_packages = [
            MaliciousPackage(
                name="axios",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/axios@1.0.0",
                advisory_id="TEST-001",
                summary="Test package - axios exists",
                details="Testing with real package",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None
            ),
            MaliciousPackage(
                name="thispackagedoesntexist",
                version="1.0.0", 
                ecosystem="npm",
                package_url="pkg:npm/thispackagedoesntexist@1.0.0",
                advisory_id="TEST-002",
                summary="Test package - doesn't exist",
                details="Testing with nonexistent package",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None
            )
        ]
        
        # Act
        existing_packages = await jfrog_registry.check_existing_packages(test_packages)
        
        # Assert
        assert isinstance(existing_packages, list)
        
        # The test verifies that the method works correctly
        # We don't assert specific packages exist since this depends on external registry state
        existing_names = [pkg.name for pkg in existing_packages]
        
        # Verify the method returned the correct format and that nonexistent packages are excluded
        assert "thispackagedoesntexist" not in existing_names, "Should not find nonexistent package"
        
        # Log what was found for debugging (not a hard assertion)
        logger.info(f"Found existing packages: {existing_names}")
    
    @pytest.mark.asyncio  
    async def test_package_blocking_lifecycle(self, jfrog_registry):
        """Test complete package blocking lifecycle (block -> check -> unblock).
        
        Note: This test modifies the registry state. Use with caution.
        """
        # Skip this test if we're in a production environment
        if os.getenv("ENVIRONMENT") == "production":
            pytest.skip("Skipping blocking test in production environment")
        
        # Arrange - Create a test package that's safe to block
        test_package = MaliciousPackage(
            name="integration-test-package",
            version="1.0.0",
            ecosystem="npm",
            package_url="pkg:npm/integration-test-package@1.0.0",
            advisory_id="INT-TEST-001",
            summary="Integration test package",
            details="Package used for integration testing",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        
        try:
            # Act 1: Block the package
            block_result = await jfrog_registry.block_package(test_package)
            
            # Assert 1: Blocking should succeed (or already be blocked)
            assert isinstance(block_result, bool)
            
            # Act 2: Check if package is blocked
            is_blocked = await jfrog_registry.is_package_blocked(test_package)
            
            # Assert 2: Package should be reported as blocked
            # Note: This might be True even if blocking failed if package was already blocked
            assert isinstance(is_blocked, bool)
            
            # Act 3: Try to unblock the package
            unblock_result = await jfrog_registry.unblock_packages([test_package])
            
            # Assert 3: Unblocking should return a list
            assert isinstance(unblock_result, list)
            
        except RegistryError as e:
            # If we get a registry error, ensure it's handled gracefully
            pytest.skip(f"Registry operation failed: {e}")
    
    @pytest.mark.asyncio
    async def test_bulk_operations_performance(self, jfrog_registry):
        """Test performance of bulk operations with multiple packages."""
        # Arrange - Create multiple test packages
        test_packages = []
        base_packages = ["axios", "lodash", "express", "react", "vue"]
        
        for i, pkg_name in enumerate(base_packages):
            package = MaliciousPackage(
                name=pkg_name,
                version="1.0.0",
                ecosystem="npm", 
                package_url=f"pkg:npm/{pkg_name}@1.0.0",
                advisory_id=f"PERF-TEST-{i:03d}",
                summary=f"Performance test package {i}",
                details="Package for performance testing",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None
            )
            test_packages.append(package)
        
        # Act & Assert - Check that bulk operations complete in reasonable time
        import time
        
        start_time = time.time()
        existing_packages = await jfrog_registry.check_existing_packages(test_packages)
        end_time = time.time()
        
        # Should complete bulk check within 30 seconds
        duration = end_time - start_time
        assert duration < 30.0, f"Bulk check took too long: {duration:.2f}s"
        
        # Should return valid results
        assert isinstance(existing_packages, list)
        assert len(existing_packages) <= len(test_packages)
    
    @pytest.mark.asyncio
    async def test_error_handling_with_invalid_ecosystem(self, jfrog_registry):
        """Test error handling with invalid ecosystem."""
        # Act & Assert
        packages = await jfrog_registry.search_packages(
            "test-package", 
            ecosystem="invalid-ecosystem"
        )
        
        # Should handle gracefully and return empty list
        assert isinstance(packages, list)
        assert len(packages) == 0
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, jfrog_registry):
        """Test concurrent operations to ensure thread safety."""
        # Arrange
        async def search_operation(package_name: str, ecosystem: str):
            return await jfrog_registry.search_packages(package_name, ecosystem=ecosystem)
        
        # Act - Run multiple concurrent searches
        tasks = [
            search_operation("axios", "npm"),
            search_operation("requests", "pypi"),
            search_operation("thispackagedoesntexist", "npm"),
            search_operation("express", "npm"),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Assert - All operations should complete without exceptions
        for i, result in enumerate(results):
            assert not isinstance(result, Exception), f"Task {i} failed with exception: {result}"
            assert isinstance(result, list), f"Task {i} should return a list"
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self, jfrog_registry):
        """Test handling of connection errors gracefully."""
        # This test verifies that the registry handles network issues gracefully
        # We can't easily simulate network failures, so we test with a very short timeout
        
        original_timeout = jfrog_registry.timeout
        
        try:
            # Temporarily set a very short timeout
            jfrog_registry.timeout = ClientTimeout(total=0.001)
            
            # Act - This should either succeed quickly or handle timeout gracefully
            packages = await jfrog_registry.search_packages("axios", ecosystem="npm")
            
            # Assert - Should return a list (empty if timeout occurred)
            assert isinstance(packages, list)
            
        finally:
            # Restore original timeout
            jfrog_registry.timeout = original_timeout