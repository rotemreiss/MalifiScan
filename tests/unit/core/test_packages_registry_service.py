"""Tests for packages registry service interface and implementations."""

import pytest
from unittest.mock import AsyncMock, Mock
from typing import List, Dict, Any
from datetime import datetime

from src.core.interfaces.packages_registry_service import PackagesRegistryService
from src.core.entities import MaliciousPackage


class MockPackagesRegistryService(PackagesRegistryService):
    """Mock implementation of PackagesRegistryService for testing."""
    
    def __init__(self):
        self.blocked_packages = set()  # Track blocked package identifiers
        self.existing_packages = []  # Packages that exist in registry
        self.healthy = True
        self.block_packages_call_count = 0
        self.block_package_call_count = 0
        self.unblock_packages_call_count = 0
        self.check_existing_call_count = 0
        self.search_packages_call_count = 0
        self.is_package_blocked_call_count = 0
        self.health_check_call_count = 0
        self.close_call_count = 0
        self.should_raise_error = False
        self.error_message = "Mock error"
        self.search_results = []
        self.is_closed = False

    def get_registry_name(self) -> str:
        """Return a fixed registry name for testing."""
        return "mock-registry"
    
    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """Mock implementation of block_packages."""
        self.block_packages_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        blocked_identifiers = []
        for package in packages:
            identifier = package.package_identifier
            if identifier not in self.blocked_packages:
                self.blocked_packages.add(identifier)
                blocked_identifiers.append(identifier)
        
        return blocked_identifiers
    
    async def block_package(self, package: MaliciousPackage) -> bool:
        """Mock implementation of block_package."""
        self.block_package_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        identifier = package.package_identifier
        if identifier not in self.blocked_packages:
            self.blocked_packages.add(identifier)
            return True
        return False  # Already blocked
    
    async def check_existing_packages(self, packages: List[MaliciousPackage]) -> List[MaliciousPackage]:
        """Mock implementation of check_existing_packages."""
        self.check_existing_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        existing = []
        for package in packages:
            if package in self.existing_packages or package.package_identifier in self.blocked_packages:
                existing.append(package)
        
        return existing
    
    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """Mock implementation of unblock_packages."""
        self.unblock_packages_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        unblocked_identifiers = []
        for package in packages:
            identifier = package.package_identifier
            if identifier in self.blocked_packages:
                self.blocked_packages.remove(identifier)
                unblocked_identifiers.append(identifier)
        
        return unblocked_identifiers
    
    async def search_packages(self, package_name: str, ecosystem: str) -> List[Dict[str, Any]]:
        """Mock implementation of search_packages."""
        self.search_packages_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        # Filter search results based on package_name and ecosystem
        results = []
        for result in self.search_results:
            if package_name.lower() in result.get('name', '').lower():
                if result.get('ecosystem') == ecosystem:
                    results.append(result)
        
        return results
    
    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """Mock implementation of is_package_blocked."""
        self.is_package_blocked_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        return package.package_identifier in self.blocked_packages
    
    async def health_check(self) -> bool:
        """Mock implementation of health_check."""
        self.health_check_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        return self.healthy and not self.is_closed
    
    async def close(self) -> None:
        """Mock implementation of close."""
        self.close_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        self.is_closed = True

    async def discover_repositories_by_ecosystem(self, ecosystem: str) -> List[str]:
        """Mock implementation of discover_repositories_by_ecosystem."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        # Return some mock repositories for testing
        mock_repositories = {
            "npm": ["npm-local", "npm-remote", "npm-virtual"],
            "pypi": ["pypi-local", "pypi-remote", "pypi-virtual"],
            "maven": ["maven-local", "maven-remote", "maven-virtual"]
        }
        return mock_repositories.get(ecosystem, [])


class TestPackagesRegistryServiceInterface:
    """Test cases for PackagesRegistryService interface."""
    
    @pytest.fixture
    def sample_packages(self):
        """Create sample malicious packages for testing."""
        return [
            MaliciousPackage(
                name="malicious-pkg-1",
                version="1.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/malicious-pkg-1@1.0.0",
                advisory_id="OSV-2023-0001",
                summary="First malicious package",
                details="Contains backdoor",
                aliases=["CVE-2023-1234"],
                affected_versions=["1.0.0"],
                database_specific={"severity": "HIGH"},
                published_at=datetime(2023, 1, 1, 12, 0, 0),
                modified_at=datetime(2023, 1, 2, 12, 0, 0)
            ),
            MaliciousPackage(
                name="malicious-pkg-2",
                version="2.1.0",
                ecosystem="npm",
                package_url="pkg:npm/malicious-pkg-2@2.1.0",
                advisory_id="OSV-2023-0002",
                summary="Second malicious package",
                details="Contains crypto miner",
                aliases=["CVE-2023-5678"],
                affected_versions=["2.1.0"],
                database_specific={"severity": "CRITICAL"},
                published_at=datetime(2023, 2, 1, 12, 0, 0),
                modified_at=datetime(2023, 2, 2, 12, 0, 0)
            )
        ]
    
    @pytest.fixture
    def mock_registry(self, sample_packages):
        """Create a mock registry service."""
        registry = MockPackagesRegistryService()
        # Add sample search results
        registry.search_results = [
            {"name": "malicious-pkg-1", "version": "1.0.0", "ecosystem": "PyPI"},
            {"name": "safe-package", "version": "2.0.0", "ecosystem": "npm"},
            {"name": "another-package", "version": "1.5.0", "ecosystem": "PyPI"}
        ]
        return registry
    
    def test_mock_registry_initialization(self):
        """Test mock registry initialization."""
        registry = MockPackagesRegistryService()
        
        assert len(registry.blocked_packages) == 0
        assert registry.existing_packages == []
        assert registry.healthy is True
        assert registry.block_packages_call_count == 0
        assert registry.block_package_call_count == 0
        assert registry.check_existing_call_count == 0
        assert registry.should_raise_error is False
    
    @pytest.mark.asyncio
    async def test_block_packages_new_packages(self, mock_registry, sample_packages):
        """Test blocking new packages."""
        result = await mock_registry.block_packages(sample_packages)
        
        assert len(result) == 2
        assert sample_packages[0].package_identifier in result
        assert sample_packages[1].package_identifier in result
        assert mock_registry.block_packages_call_count == 1
        assert len(mock_registry.blocked_packages) == 2
    
    @pytest.mark.asyncio
    async def test_block_packages_already_blocked(self, mock_registry, sample_packages):
        """Test blocking packages that are already blocked."""
        # Block packages first time
        await mock_registry.block_packages(sample_packages)
        
        # Try to block same packages again
        result = await mock_registry.block_packages(sample_packages)
        
        assert len(result) == 0  # No new packages blocked
        assert mock_registry.block_packages_call_count == 2
        assert len(mock_registry.blocked_packages) == 2  # Still only 2
    
    @pytest.mark.asyncio
    async def test_block_packages_mixed_scenario(self, mock_registry, sample_packages):
        """Test blocking mix of new and already blocked packages."""
        # Block first package
        await mock_registry.block_packages([sample_packages[0]])
        
        # Try to block both packages
        result = await mock_registry.block_packages(sample_packages)
        
        assert len(result) == 1  # Only second package was newly blocked
        assert sample_packages[1].package_identifier in result
        assert sample_packages[0].package_identifier not in result
    
    @pytest.mark.asyncio
    async def test_block_packages_empty_list(self, mock_registry):
        """Test blocking empty list of packages."""
        result = await mock_registry.block_packages([])
        
        assert len(result) == 0
        assert mock_registry.block_packages_call_count == 1
        assert len(mock_registry.blocked_packages) == 0
    
    @pytest.mark.asyncio
    async def test_block_packages_error(self, mock_registry, sample_packages):
        """Test block_packages when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Registry connection failed"
        
        with pytest.raises(Exception, match="Registry connection failed"):
            await mock_registry.block_packages(sample_packages)
        
        assert mock_registry.block_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_block_package_new_package(self, mock_registry, sample_packages):
        """Test blocking a single new package."""
        result = await mock_registry.block_package(sample_packages[0])
        
        assert result is True
        assert mock_registry.block_package_call_count == 1
        assert sample_packages[0].package_identifier in mock_registry.blocked_packages
    
    @pytest.mark.asyncio
    async def test_block_package_already_blocked(self, mock_registry, sample_packages):
        """Test blocking a single package that's already blocked."""
        # Block package first
        await mock_registry.block_package(sample_packages[0])
        
        # Try to block same package again
        result = await mock_registry.block_package(sample_packages[0])
        
        assert result is False
        assert mock_registry.block_package_call_count == 2
    
    @pytest.mark.asyncio
    async def test_block_package_error(self, mock_registry, sample_packages):
        """Test block_package when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Block operation failed"
        
        with pytest.raises(Exception, match="Block operation failed"):
            await mock_registry.block_package(sample_packages[0])
        
        assert mock_registry.block_package_call_count == 1
    
    @pytest.mark.asyncio
    async def test_check_existing_packages_none_exist(self, mock_registry, sample_packages):
        """Test checking existing packages when none exist."""
        result = await mock_registry.check_existing_packages(sample_packages)
        
        assert len(result) == 0
        assert mock_registry.check_existing_call_count == 1
    
    @pytest.mark.asyncio
    async def test_check_existing_packages_some_exist(self, mock_registry, sample_packages):
        """Test checking existing packages when some exist."""
        # Set first package as existing
        mock_registry.existing_packages = [sample_packages[0]]
        
        result = await mock_registry.check_existing_packages(sample_packages)
        
        assert len(result) == 1
        assert result[0] == sample_packages[0]
        assert mock_registry.check_existing_call_count == 1
    
    @pytest.mark.asyncio
    async def test_check_existing_packages_blocked_packages(self, mock_registry, sample_packages):
        """Test checking existing packages includes blocked packages."""
        # Block first package
        await mock_registry.block_package(sample_packages[0])
        
        result = await mock_registry.check_existing_packages(sample_packages)
        
        assert len(result) == 1
        assert result[0] == sample_packages[0]
    
    @pytest.mark.asyncio
    async def test_check_existing_packages_error(self, mock_registry, sample_packages):
        """Test check_existing_packages when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Check operation failed"
        
        with pytest.raises(Exception, match="Check operation failed"):
            await mock_registry.check_existing_packages(sample_packages)
        
        assert mock_registry.check_existing_call_count == 1
    
    @pytest.mark.asyncio
    async def test_search_packages_basic(self, mock_registry):
        """Test basic package search."""
        result = await mock_registry.search_packages("malicious", "PyPI")
        
        assert len(result) == 1
        assert result[0]["name"] == "malicious-pkg-1"
        assert mock_registry.search_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_search_packages_no_matches(self, mock_registry):
        """Test package search with no matches."""
        result = await mock_registry.search_packages("nonexistent", "PyPI")
        
        assert len(result) == 0
        assert mock_registry.search_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_search_packages_different_ecosystem(self, mock_registry):
        """Test package search with different ecosystem."""
        result = await mock_registry.search_packages("safe", "npm")
        
        assert len(result) == 1
        assert result[0]["name"] == "safe-package"
        assert result[0]["ecosystem"] == "npm"
        assert mock_registry.search_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_search_packages_error(self, mock_registry):
        """Test search_packages when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Search operation failed"
        
        with pytest.raises(Exception, match="Search operation failed"):
            await mock_registry.search_packages("test", "PyPI")
        
        assert mock_registry.search_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_unblock_packages_success(self, mock_registry, sample_packages):
        """Test unblocking packages that are blocked."""
        # First block the packages
        await mock_registry.block_packages(sample_packages)
        
        # Now unblock them
        result = await mock_registry.unblock_packages(sample_packages)
        
        assert len(result) == 2
        assert sample_packages[0].package_identifier in result
        assert sample_packages[1].package_identifier in result
        assert mock_registry.unblock_packages_call_count == 1
        assert len(mock_registry.blocked_packages) == 0
    
    @pytest.mark.asyncio
    async def test_unblock_packages_not_blocked(self, mock_registry, sample_packages):
        """Test unblocking packages that are not blocked."""
        result = await mock_registry.unblock_packages(sample_packages)
        
        assert len(result) == 0  # Nothing to unblock
        assert mock_registry.unblock_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_unblock_packages_error(self, mock_registry, sample_packages):
        """Test unblock_packages when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Unblock operation failed"
        
        with pytest.raises(Exception, match="Unblock operation failed"):
            await mock_registry.unblock_packages(sample_packages)
        
        assert mock_registry.unblock_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_is_package_blocked_true(self, mock_registry, sample_packages):
        """Test is_package_blocked when package is blocked."""
        # Block the package first
        await mock_registry.block_package(sample_packages[0])
        
        result = await mock_registry.is_package_blocked(sample_packages[0])
        
        assert result is True
        assert mock_registry.is_package_blocked_call_count == 1
    
    @pytest.mark.asyncio
    async def test_is_package_blocked_false(self, mock_registry, sample_packages):
        """Test is_package_blocked when package is not blocked."""
        result = await mock_registry.is_package_blocked(sample_packages[0])
        
        assert result is False
        assert mock_registry.is_package_blocked_call_count == 1
    
    @pytest.mark.asyncio
    async def test_is_package_blocked_error(self, mock_registry, sample_packages):
        """Test is_package_blocked when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Check blocked status failed"
        
        with pytest.raises(Exception, match="Check blocked status failed"):
            await mock_registry.is_package_blocked(sample_packages[0])
        
        assert mock_registry.is_package_blocked_call_count == 1
    
    @pytest.mark.asyncio
    async def test_close_success(self, mock_registry):
        """Test successful close operation."""
        await mock_registry.close()
        
        assert mock_registry.is_closed is True
        assert mock_registry.close_call_count == 1
        
        # Health check should return False after close
        health = await mock_registry.health_check()
        assert health is False
    
    @pytest.mark.asyncio
    async def test_close_error(self, mock_registry):
        """Test close when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Close operation failed"
        
        with pytest.raises(Exception, match="Close operation failed"):
            await mock_registry.close()
        
        assert mock_registry.close_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_registry):
        """Test health check when service is healthy."""
        result = await mock_registry.health_check()
        
        assert result is True
        assert mock_registry.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_registry):
        """Test health check when service is unhealthy."""
        mock_registry.healthy = False
        
        result = await mock_registry.health_check()
        
        assert result is False
        assert mock_registry.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_error(self, mock_registry):
        """Test health check when error occurs."""
        mock_registry.should_raise_error = True
        mock_registry.error_message = "Health check failed"
        
        with pytest.raises(Exception, match="Health check failed"):
            await mock_registry.health_check()
        
        assert mock_registry.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_interface_contract_compliance(self, mock_registry, sample_packages):
        """Test that mock implementation complies with interface contract."""
        # Verify it's an instance of the interface
        assert isinstance(mock_registry, PackagesRegistryService)
        
        # Verify methods exist and are callable
        assert hasattr(mock_registry, 'block_packages')
        assert hasattr(mock_registry, 'block_package')
        assert hasattr(mock_registry, 'check_existing_packages')
        assert hasattr(mock_registry, 'unblock_packages')
        assert hasattr(mock_registry, 'search_packages')
        assert hasattr(mock_registry, 'is_package_blocked')
        assert hasattr(mock_registry, 'health_check')
        assert hasattr(mock_registry, 'close')
        
        # Test all methods return expected types
        block_result = await mock_registry.block_packages(sample_packages)
        assert isinstance(block_result, list)
        
        single_block_result = await mock_registry.block_package(sample_packages[0])
        assert isinstance(single_block_result, bool)
        
        existing_result = await mock_registry.check_existing_packages(sample_packages)
        assert isinstance(existing_result, list)
        
        unblock_result = await mock_registry.unblock_packages(sample_packages)
        assert isinstance(unblock_result, list)
        
        search_result = await mock_registry.search_packages("test", "PyPI")
        assert isinstance(search_result, list)
        
        blocked_result = await mock_registry.is_package_blocked(sample_packages[0])
        assert isinstance(blocked_result, bool)
        
        health_result = await mock_registry.health_check()
        assert isinstance(health_result, bool)
        
        # Close doesn't return anything
        await mock_registry.close()
    
    def test_interface_is_abstract(self):
        """Test that PackagesRegistryService interface cannot be instantiated directly."""
        with pytest.raises(TypeError):
            PackagesRegistryService()  # pylint: disable=abstract-class-instantiated
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mock_registry, sample_packages):
        """Test concurrent operations on the registry."""
        import asyncio
        
        # Create multiple concurrent tasks
        tasks = [
            mock_registry.block_packages([sample_packages[0]]),
            mock_registry.block_package(sample_packages[1]),
            mock_registry.search_packages("test", "PyPI"),
            mock_registry.health_check(),
            mock_registry.is_package_blocked(sample_packages[0])
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify results
        assert len(results) == 5
        assert isinstance(results[0], list)   # block_packages result
        assert isinstance(results[1], bool)   # block_package result  
        assert isinstance(results[2], list)   # search_packages result
        assert isinstance(results[3], bool)   # health_check result
        assert isinstance(results[4], bool)   # is_package_blocked result
        
        # Verify call counters
        assert mock_registry.block_packages_call_count == 1
        assert mock_registry.block_package_call_count == 1
        assert mock_registry.search_packages_call_count == 1
        assert mock_registry.health_check_call_count == 1
        assert mock_registry.is_package_blocked_call_count == 1
    
    @pytest.mark.asyncio
    async def test_state_persistence_across_calls(self, mock_registry, sample_packages):
        """Test that registry state persists across multiple calls."""
        # Block some packages
        await mock_registry.block_packages([sample_packages[0]])
        await mock_registry.block_package(sample_packages[1])
        
        # Verify state persists
        existing = await mock_registry.check_existing_packages(sample_packages)
        assert len(existing) == 2
        
        # Check individual package blocked status
        blocked_0 = await mock_registry.is_package_blocked(sample_packages[0])
        blocked_1 = await mock_registry.is_package_blocked(sample_packages[1])
        assert blocked_0 is True
        assert blocked_1 is True
        
        # Try to block again - should return empty since already blocked
        new_blocks = await mock_registry.block_packages(sample_packages)
        assert len(new_blocks) == 0
        
        # Unblock and verify state changes
        unblocked = await mock_registry.unblock_packages([sample_packages[0]])
        assert len(unblocked) == 1
        
        # Check that only one is still blocked
        blocked_0_after = await mock_registry.is_package_blocked(sample_packages[0])
        blocked_1_after = await mock_registry.is_package_blocked(sample_packages[1])
        assert blocked_0_after is False
        assert blocked_1_after is True
    
    @pytest.mark.asyncio
    async def test_full_lifecycle_workflow(self, mock_registry, sample_packages):
        """Test a complete workflow from block to unblock."""
        # 1. Initially no packages are blocked
        for package in sample_packages:
            blocked = await mock_registry.is_package_blocked(package)
            assert blocked is False
        
        # 2. Block all packages
        blocked_ids = await mock_registry.block_packages(sample_packages)
        assert len(blocked_ids) == 2
        
        # 3. Verify all are blocked
        for package in sample_packages:
            blocked = await mock_registry.is_package_blocked(package)
            assert blocked is True
        
        # 4. Check existing returns all packages
        existing = await mock_registry.check_existing_packages(sample_packages)
        assert len(existing) == 2
        
        # 5. Unblock one package
        unblocked_ids = await mock_registry.unblock_packages([sample_packages[0]])
        assert len(unblocked_ids) == 1
        
        # 6. Verify mixed state
        blocked_0 = await mock_registry.is_package_blocked(sample_packages[0])
        blocked_1 = await mock_registry.is_package_blocked(sample_packages[1])
        assert blocked_0 is False
        assert blocked_1 is True
        
        # 7. Close registry
        await mock_registry.close()
        health = await mock_registry.health_check()
        assert health is False