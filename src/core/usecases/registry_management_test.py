"""Test cases for registry management use case."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.usecases.registry_management import RegistryManagementUseCase


@pytest.fixture
def mock_registry_service():
    """Mock registry service for testing."""
    service = AsyncMock()
    service.get_registry_name.return_value = "Test Registry"
    return service


@pytest.fixture
def registry_usecase(mock_registry_service):
    """Registry management use case with mocked dependencies."""
    return RegistryManagementUseCase(mock_registry_service)


@pytest.mark.asyncio
async def test_search_package_success(registry_usecase, mock_registry_service):
    """Test successful package search."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.search_packages.return_value = [
        {"name": "test-package", "version": "1.0.0"}
    ]
    mock_registry_service.is_package_blocked.return_value = False
    
    # Act
    result = await registry_usecase.search_package("test-package", "npm")
    
    # Assert
    assert result["success"] is True
    assert result["package_name"] == "test-package"
    assert result["ecosystem"] == "npm"
    assert result["registry_healthy"] is True
    assert result["results_count"] == 1
    assert result["is_blocked"] is False
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_search_package_registry_unhealthy(registry_usecase, mock_registry_service):
    """Test package search when registry is unhealthy."""
    # Arrange
    mock_registry_service.health_check.return_value = False
    
    # Act
    result = await registry_usecase.search_package("test-package", "npm")
    
    # Assert
    assert result["success"] is False
    assert result["error"] == "Registry is not accessible"
    assert result["registry_healthy"] is False
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_block_package_success(registry_usecase, mock_registry_service):
    """Test successful package blocking."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = False
    mock_registry_service.block_package.return_value = True
    
    # Act
    result = await registry_usecase.block_package("evil-package", "npm", "1.0.0")
    
    # Assert
    assert result["success"] is True
    assert "Successfully blocked" in result["message"]
    assert result["already_blocked"] is False
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_block_package_already_blocked(registry_usecase, mock_registry_service):
    """Test blocking package that is already blocked."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = True
    
    # Act
    result = await registry_usecase.block_package("evil-package", "npm", "1.0.0")
    
    # Assert
    assert result["success"] is True
    assert "already blocked" in result["message"]
    assert result["already_blocked"] is True
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_unblock_package_success(registry_usecase, mock_registry_service):
    """Test successful package unblocking."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = True
    mock_registry_service.unblock_package.return_value = True
    
    # Act
    result = await registry_usecase.unblock_package("evil-package", "npm", "1.0.0")
    
    # Assert
    assert result["success"] is True
    assert "Successfully unblocked" in result["message"]
    assert result["was_blocked"] is True
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_unblock_package_not_blocked(registry_usecase, mock_registry_service):
    """Test unblocking package that is not currently blocked."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = False
    
    # Act
    result = await registry_usecase.unblock_package("evil-package", "npm", "1.0.0")
    
    # Assert
    assert result["success"] is True
    assert "not currently blocked" in result["message"]
    assert result["was_blocked"] is False
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_list_blocked_packages_success(registry_usecase, mock_registry_service):
    """Test successful listing of blocked packages."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.list_blocked_packages.return_value = [
        {"name": "evil-package1", "pattern": "evil-package1/*"},
        {"name": "evil-package2", "pattern": "evil-package2/*"}
    ]
    
    # Act
    result = await registry_usecase.list_blocked_packages("npm")
    
    # Assert
    assert result["success"] is True
    assert result["count"] == 2
    assert len(result["blocked_packages"]) == 2
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_health_check_success(registry_usecase, mock_registry_service):
    """Test successful health check."""
    # Arrange
    mock_registry_service.health_check.return_value = True
    mock_registry_service.get_registry_name.return_value = "Test Registry"
    
    # Act
    result = await registry_usecase.health_check()
    
    # Assert
    assert result["success"] is True
    assert result["healthy"] is True
    assert result["registry_name"] == "Test Registry"
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_exception_handling(registry_usecase, mock_registry_service):
    """Test exception handling in use case methods."""
    # Arrange
    mock_registry_service.health_check.side_effect = Exception("Connection error")
    
    # Act
    result = await registry_usecase.search_package("test-package", "npm")
    
    # Assert
    assert result["success"] is False
    assert "Connection error" in result["error"]
    mock_registry_service.close.assert_called_once()