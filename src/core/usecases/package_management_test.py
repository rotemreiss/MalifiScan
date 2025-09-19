"""Tests for package_management use case."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.core.usecases.package_management import PackageManagementUseCase
from src.core.entities.malicious_package import MaliciousPackage


class TestPackageManagementUseCase:
    """Test cases for PackageManagementUseCase."""

    @pytest.fixture
    def mock_registry_service(self):
        """Mock registry service for testing."""
        service = Mock()
        service.health_check = AsyncMock(return_value=True)
        service.search_packages = AsyncMock(return_value=[])
        service.is_package_blocked = AsyncMock(return_value=False)
        service.block_package = AsyncMock(return_value=True)
        service.close = AsyncMock()
        return service

    @pytest.fixture
    def mock_storage_service(self):
        """Mock storage service for testing."""
        service = Mock()
        service.store_malicious_packages = AsyncMock()
        return service

    @pytest.fixture
    def mock_logger(self):
        """Mock logger for testing."""
        with patch('src.core.usecases.package_management.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            yield mock_logger

    @pytest.fixture
    def use_case(self, mock_registry_service, mock_storage_service):
        """Create PackageManagementUseCase instance for testing."""
        return PackageManagementUseCase(mock_registry_service, mock_storage_service)

    def test_init(self, mock_registry_service, mock_storage_service, mock_logger):
        """Test initialization of PackageManagementUseCase."""
        use_case = PackageManagementUseCase(mock_registry_service, mock_storage_service)
        
        assert use_case.registry_service == mock_registry_service
        assert use_case.storage_service == mock_storage_service
        assert use_case.logger is not None

    @pytest.mark.asyncio
    async def test_search_package_successful(self, use_case, mock_registry_service, mock_logger):
        """Test successful package search."""
        package_name = "test-package"
        ecosystem = "npm"
        search_results = [{"name": "test-package", "version": "1.0.0"}]
        
        mock_registry_service.search_packages.return_value = search_results
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is True
        assert result["package_name"] == package_name
        assert result["ecosystem"] == ecosystem
        assert result["registry_healthy"] is True
        assert result["search_results"] == search_results
        assert result["is_blocked"] is False
        assert result["results_count"] == 1
        
        mock_registry_service.health_check.assert_called_once()
        mock_registry_service.search_packages.assert_called_once_with(package_name, ecosystem)
        mock_registry_service.is_package_blocked.assert_called_once()
        mock_registry_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_package_default_ecosystem(self, use_case, mock_registry_service, mock_logger):
        """Test package search with default ecosystem."""
        package_name = "test-package"
        
        result = await use_case.search_package(package_name)
        
        assert result["ecosystem"] == "npm"  # Default ecosystem
        mock_registry_service.search_packages.assert_called_once_with(package_name, "npm")

    @pytest.mark.asyncio
    async def test_search_package_registry_unhealthy(self, use_case, mock_registry_service, mock_logger):
        """Test package search when registry is unhealthy."""
        package_name = "test-package"
        ecosystem = "npm"
        
        mock_registry_service.health_check.return_value = False
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is False
        assert result["package_name"] == package_name
        assert result["ecosystem"] == ecosystem
        assert result["registry_healthy"] is False
        assert result["search_results"] == []
        assert result["is_blocked"] is False
        assert result["error"] == "Registry not accessible"
        
        mock_registry_service.health_check.assert_called_once()
        mock_registry_service.search_packages.assert_not_called()
        mock_registry_service.is_package_blocked.assert_not_called()
        mock_registry_service.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_package_blocked(self, use_case, mock_registry_service, mock_logger):
        """Test package search when package is blocked."""
        package_name = "malicious-package"
        ecosystem = "npm"
        
        mock_registry_service.is_package_blocked.return_value = True
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is True
        assert result["is_blocked"] is True

    @pytest.mark.asyncio
    async def test_search_package_empty_results(self, use_case, mock_registry_service, mock_logger):
        """Test package search with no results."""
        package_name = "nonexistent-package"
        ecosystem = "npm"
        
        mock_registry_service.search_packages.return_value = []
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is True
        assert result["search_results"] == []
        assert result["results_count"] == 0

    @pytest.mark.asyncio
    async def test_search_package_multiple_results(self, use_case, mock_registry_service, mock_logger):
        """Test package search with multiple results."""
        package_name = "popular-package"
        ecosystem = "npm"
        search_results = [
            {"name": "popular-package", "version": "1.0.0"},
            {"name": "popular-package", "version": "2.0.0"},
            {"name": "popular-package-addon", "version": "1.0.0"}
        ]
        
        mock_registry_service.search_packages.return_value = search_results
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is True
        assert result["results_count"] == 3
        assert len(result["search_results"]) == 3

    @pytest.mark.asyncio
    async def test_search_package_different_ecosystems(self, use_case, mock_registry_service, mock_logger):
        """Test package search with different ecosystems."""
        package_name = "test-package"
        
        # Test PyPI ecosystem
        result = await use_case.search_package(package_name, "pypi")
        assert result["ecosystem"] == "pypi"
        
        # Test Maven ecosystem
        result = await use_case.search_package(package_name, "maven")
        assert result["ecosystem"] == "maven"

    @pytest.mark.asyncio
    async def test_search_package_exception_during_search(self, use_case, mock_registry_service, mock_logger):
        """Test package search when search_packages raises exception."""
        package_name = "test-package"
        ecosystem = "npm"
        
        mock_registry_service.search_packages.side_effect = Exception("Search failed")
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is False
        assert result["error"] == "Search failed"
        assert result["registry_healthy"] is False
        assert result["search_results"] == []
        assert result["is_blocked"] is False
        
        # Should still try to cleanup
        mock_registry_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_package_exception_during_is_blocked_check(self, use_case, mock_registry_service, mock_logger):
        """Test package search when is_package_blocked raises exception."""
        package_name = "test-package"
        ecosystem = "npm"
        
        mock_registry_service.is_package_blocked.side_effect = Exception("Block check failed")
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is False
        assert result["error"] == "Block check failed"

    @pytest.mark.asyncio
    async def test_search_package_cleanup_exception_ignored(self, use_case, mock_registry_service, mock_logger):
        """Test that cleanup exceptions are ignored during error handling."""
        package_name = "test-package"
        ecosystem = "npm"
        
        mock_registry_service.search_packages.side_effect = Exception("Search failed")
        mock_registry_service.close.side_effect = Exception("Cleanup failed")
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is False
        assert result["error"] == "Search failed"  # Original error, not cleanup error

    @pytest.mark.asyncio
    async def test_search_package_malicious_package_creation(self, use_case, mock_registry_service, mock_logger):
        """Test that MaliciousPackage is created correctly for blocked check."""
        package_name = "test-package"
        ecosystem = "npm"
        
        await use_case.search_package(package_name, ecosystem)
        
        # Verify the MaliciousPackage passed to is_package_blocked
        call_args = mock_registry_service.is_package_blocked.call_args[0]
        test_package = call_args[0]
        
        assert isinstance(test_package, MaliciousPackage)
        assert test_package.name == package_name
        assert test_package.ecosystem == ecosystem
        assert test_package.version is None
        assert test_package.package_url == f"pkg:{ecosystem.lower()}/{package_name}"
        assert test_package.advisory_id == "CLI-SEARCH"
        assert test_package.summary == "CLI search test package"

    @pytest.mark.asyncio
    async def test_block_package_successful(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test successful package blocking."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "1.0.0"
        
        result = await use_case.block_package(package_name, ecosystem, version)
        
        assert result["success"] is True
        assert result["package_name"] == package_name
        assert result["ecosystem"] == ecosystem
        assert result["version"] == version
        assert "Successfully blocked" in result["message"]
        
        mock_registry_service.block_package.assert_called_once()
        mock_storage_service.store_malicious_packages.assert_called_once()

    @pytest.mark.asyncio
    async def test_block_package_default_parameters(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking with default parameters."""
        package_name = "malicious-package"
        
        result = await use_case.block_package(package_name)
        
        assert result["ecosystem"] == "npm"  # Default ecosystem
        assert result["version"] == "*"  # Default version

    @pytest.mark.asyncio
    async def test_block_package_wildcard_version(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking with wildcard version."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "*"
        
        await use_case.block_package(package_name, ecosystem, version)
        
        # Verify the MaliciousPackage creation
        call_args = mock_registry_service.block_package.call_args[0]
        package = call_args[0]
        
        assert package.version == "*"
        assert package.affected_versions == []  # Empty for wildcard

    @pytest.mark.asyncio
    async def test_block_package_specific_version(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking with specific version."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "1.2.3"
        
        await use_case.block_package(package_name, ecosystem, version)
        
        # Verify the MaliciousPackage creation
        call_args = mock_registry_service.block_package.call_args[0]
        package = call_args[0]
        
        assert package.version == "1.2.3"
        assert package.affected_versions == ["1.2.3"]

    @pytest.mark.asyncio
    async def test_block_package_malicious_package_fields(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test that MaliciousPackage is created with correct fields for blocking."""
        package_name = "malicious-package"
        ecosystem = "pypi"
        version = "2.0.0"
        
        with patch('src.core.usecases.package_management.datetime') as mock_datetime:
            mock_now = datetime(2023, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now
            
            await use_case.block_package(package_name, ecosystem, version)
        
        call_args = mock_registry_service.block_package.call_args[0]
        package = call_args[0]
        
        assert package.name == package_name
        assert package.ecosystem == ecosystem
        assert package.version == version
        assert package.package_url == f"pkg:{ecosystem.lower()}/{package_name}@{version}"
        assert package.advisory_id == "CLI-MANUAL-BLOCK"
        assert "Manually blocked via CLI at" in package.summary
        assert package.details == "Package blocked using CLI testing tool"
        assert package.aliases == []
        assert package.database_specific == {}
        assert package.published_at is None
        assert package.modified_at is None

    @pytest.mark.asyncio
    async def test_block_package_registry_failure(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking when registry block operation fails."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "1.0.0"
        
        mock_registry_service.block_package.return_value = False
        
        result = await use_case.block_package(package_name, ecosystem, version)
        
        assert result["success"] is False
        assert result["error"] == f"Failed to block {package_name}"
        
        mock_registry_service.block_package.assert_called_once()
        mock_storage_service.store_malicious_packages.assert_not_called()

    @pytest.mark.asyncio
    async def test_block_package_exception(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking when an exception occurs."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "1.0.0"
        
        mock_registry_service.block_package.side_effect = Exception("Registry error")
        
        result = await use_case.block_package(package_name, ecosystem, version)
        
        assert result["success"] is False
        assert result["error"] == "Registry error"
        
        mock_storage_service.store_malicious_packages.assert_not_called()

    @pytest.mark.asyncio
    async def test_block_package_storage_exception_after_successful_block(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test package blocking when storage fails after successful registry block."""
        package_name = "malicious-package"
        ecosystem = "npm"
        version = "1.0.0"
        
        mock_storage_service.store_malicious_packages.side_effect = Exception("Storage error")
        
        result = await use_case.block_package(package_name, ecosystem, version)
        
        # Should still fail overall if storage fails
        assert result["success"] is False
        assert result["error"] == "Storage error"

    @pytest.mark.asyncio
    async def test_different_ecosystems_package_urls(self, use_case, mock_registry_service, mock_storage_service, mock_logger):
        """Test that package URLs are formatted correctly for different ecosystems."""
        test_cases = [
            ("npm", "test-package", "1.0.0", "pkg:npm/test-package@1.0.0"),
            ("pypi", "test-package", "2.0.0", "pkg:pypi/test-package@2.0.0"),
            ("Maven", "test-package", "3.0.0", "pkg:maven/test-package@3.0.0"),  # Should be lowercased
        ]
        
        for ecosystem, package_name, version, expected_url in test_cases:
            await use_case.block_package(package_name, ecosystem, version)
            
            call_args = mock_registry_service.block_package.call_args[0]
            package = call_args[0]
            
            assert package.package_url == expected_url

    @pytest.mark.asyncio
    async def test_search_package_case_sensitive_ecosystem(self, use_case, mock_registry_service, mock_logger):
        """Test that ecosystem case is preserved in search results but lowercased in URLs."""
        package_name = "test-package"
        ecosystem = "PyPI"  # Mixed case
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["ecosystem"] == "PyPI"  # Preserved in result
        
        # Check the test package creation
        call_args = mock_registry_service.is_package_blocked.call_args[0]
        test_package = call_args[0]
        assert test_package.package_url == f"pkg:pypi/{package_name}"  # Lowercased in URL

    @pytest.mark.asyncio
    async def test_logging_calls(self, mock_registry_service, mock_storage_service):
        """Test that appropriate logging calls are made."""
        with patch('src.core.usecases.package_management.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            use_case = PackageManagementUseCase(mock_registry_service, mock_storage_service)
            package_name = "test-package"
            ecosystem = "npm"
            
            # Test search logging
            await use_case.search_package(package_name, ecosystem)
            
            mock_logger.info.assert_any_call(f"Searching for package: {package_name} ({ecosystem})")
            mock_logger.info.assert_any_call(f"Package search completed: 0 results found, blocked: False")
            
            # Reset mock
            mock_logger.reset_mock()
            
            # Test block logging
            await use_case.block_package(package_name, ecosystem, "1.0.0")
            
            mock_logger.info.assert_any_call(f"Blocking package: {package_name} ({ecosystem}) version 1.0.0")
            mock_logger.info.assert_any_call(f"Successfully blocked {package_name}")

    @pytest.mark.asyncio
    async def test_search_package_registry_service_none_during_cleanup(self, mock_logger):
        """Test search_package when registry_service becomes None during error handling."""
        package_name = "test-package"
        ecosystem = "npm"
        
        # Create a use case where registry_service is None from the start
        use_case = PackageManagementUseCase(None, Mock())  # type: ignore
        
        result = await use_case.search_package(package_name, ecosystem)
        
        assert result["success"] is False
        assert "'NoneType' object has no attribute 'health_check'" in result["error"]
        # Should not raise an exception during cleanup