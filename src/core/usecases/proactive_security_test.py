"""Test cases for proactive security use case."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.core.entities.malicious_package import MaliciousPackage
from src.core.usecases.proactive_security import ProactiveSecurityUseCase


@pytest.fixture
def mock_packages_feed():
    """Mock packages feed for testing."""
    return AsyncMock()


@pytest.fixture
def mock_registry_service():
    """Mock registry service for testing."""
    return AsyncMock()


@pytest.fixture
def proactive_usecase(mock_packages_feed, mock_registry_service):
    """Proactive security use case with mocked dependencies."""
    return ProactiveSecurityUseCase(mock_packages_feed, mock_registry_service)


@pytest.fixture
def sample_malicious_packages():
    """Sample malicious packages for testing."""
    return [
        MaliciousPackage(
            advisory_id="OSV-2023-001",
            name="evil-package-1",
            ecosystem="npm",
            version="1.0.0",
            package_url="https://example.com/evil-package-1"
        ),
        MaliciousPackage(
            advisory_id="OSV-2023-002",
            name="evil-package-2",
            ecosystem="npm",
            version="2.0.0",
            package_url="https://example.com/evil-package-2"
        ),
        MaliciousPackage(
            advisory_id="OSV-2023-003",
            name="malicious-pypi",
            ecosystem="pypi",
            version="1.5.0",
            package_url="https://example.com/malicious-pypi"
        )
    ]


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_success(
    proactive_usecase, 
    mock_packages_feed, 
    mock_registry_service, 
    sample_malicious_packages
):
    """Test successful proactive blocking of malicious packages."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = False
    mock_registry_service.block_package.return_value = True
    
    progress_calls = []
    def progress_callback(message, current, total):
        progress_calls.append((message, current, total))
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm",
        limit=10,
        progress_callback=progress_callback
    )
    
    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2  # Only npm packages
    assert result["success_count"] == 2
    assert result["already_blocked_count"] == 0
    assert result["error_count"] == 0
    assert len(result["blocked_packages"]) == 2
    assert len(result["already_blocked"]) == 0
    assert len(result["errors"]) == 0
    
    # Verify progress callbacks were called
    assert len(progress_calls) > 0
    assert progress_calls[-1] == ("Proactive blocking complete", 100, 100)
    
    # Verify service calls
    mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
        max_packages=10,
        hours=6
    )
    mock_registry_service.health_check.assert_called_once()
    assert mock_registry_service.is_package_blocked.call_count == 2
    assert mock_registry_service.block_package.call_count == 2
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_no_packages(
    proactive_usecase, 
    mock_packages_feed, 
    mock_registry_service
):
    """Test proactive blocking when no malicious packages are found."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = []
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm"
    )
    
    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 0
    assert len(result["blocked_packages"]) == 0
    assert len(result["already_blocked"]) == 0
    assert len(result["errors"]) == 0


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_registry_unhealthy(
    proactive_usecase, 
    mock_packages_feed, 
    mock_registry_service, 
    sample_malicious_packages
):
    """Test proactive blocking when registry is unhealthy."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages[:2]  # npm packages
    mock_registry_service.health_check.return_value = False
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm"
    )
    
    # Assert
    assert result["success"] is False
    assert "not accessible" in result["error"]
    assert result["total_packages"] == 2
    assert len(result["errors"]) == 1


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_already_blocked(
    proactive_usecase, 
    mock_packages_feed, 
    mock_registry_service, 
    sample_malicious_packages
):
    """Test proactive blocking when packages are already blocked."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages[:2]  # npm packages
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = True  # Already blocked
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm"
    )
    
    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2
    assert result["success_count"] == 0
    assert result["already_blocked_count"] == 2
    assert len(result["blocked_packages"]) == 0
    assert len(result["already_blocked"]) == 2
    
    # Should not attempt to block if already blocked
    mock_registry_service.block_package.assert_not_called()


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_mixed_results(
    proactive_usecase, 
    mock_packages_feed, 
    mock_registry_service, 
    sample_malicious_packages
):
    """Test proactive blocking with mixed success/failure results."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages[:2]  # npm packages
    mock_registry_service.health_check.return_value = True
    
    # First package: not blocked, successful block
    # Second package: not blocked, failed block
    mock_registry_service.is_package_blocked.side_effect = [False, False]
    mock_registry_service.block_package.side_effect = [True, False]
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm"
    )
    
    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2
    assert result["success_count"] == 1
    assert result["already_blocked_count"] == 0
    assert result["error_count"] == 1
    assert len(result["blocked_packages"]) == 1
    assert len(result["already_blocked"]) == 0
    assert len(result["errors"]) == 1


@pytest.mark.asyncio
async def test_unblock_packages_by_criteria_dry_run(
    proactive_usecase, 
    mock_registry_service
):
    """Test bulk unblocking in dry run mode."""
    # Arrange
    blocked_packages = [
        {"name": "evil-package-1", "pattern": "evil-package-1/*"},
        {"name": "evil-package-2", "pattern": "evil-package-2/*"},
        {"name": "good-package", "pattern": "good-package/*"}
    ]
    mock_registry_service.list_blocked_packages.return_value = blocked_packages
    
    # Act
    result = await proactive_usecase.unblock_packages_by_criteria(
        ecosystem="npm",
        package_pattern="evil-*",
        dry_run=True
    )
    
    # Assert
    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["total_blocked"] == 3
    assert len(result["matching_packages"]) == 2  # Only evil-* packages
    assert len(result["unblocked_packages"]) == 0  # Dry run
    assert "Would unblock 2 packages" in result["message"]
    
    # Should not actually unblock anything
    mock_registry_service.unblock_package.assert_not_called()


@pytest.mark.asyncio
async def test_unblock_packages_by_criteria_actual_run(
    proactive_usecase, 
    mock_registry_service
):
    """Test bulk unblocking in actual mode."""
    # Arrange
    blocked_packages = [
        {"name": "evil-package-1", "pattern": "evil-package-1/*"},
        {"name": "evil-package-2", "pattern": "evil-package-2/*"}
    ]
    mock_registry_service.list_blocked_packages.return_value = blocked_packages
    mock_registry_service.unblock_package.return_value = True
    
    # Act
    result = await proactive_usecase.unblock_packages_by_criteria(
        ecosystem="npm",
        package_pattern="evil-*",
        dry_run=False
    )
    
    # Assert
    assert result["success"] is True
    assert result["dry_run"] is False
    assert result["total_blocked"] == 2
    assert result["unblocked_count"] == 2
    assert result["error_count"] == 0
    assert len(result["unblocked_packages"]) == 2
    
    # Should attempt to unblock matching packages
    assert mock_registry_service.unblock_package.call_count == 2


@pytest.mark.asyncio
async def test_exception_handling(proactive_usecase, mock_packages_feed, mock_registry_service):
    """Test exception handling in proactive security operations."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed connection error")
    
    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6,
        ecosystem="npm"
    )
    
    # Assert
    assert result["success"] is False
    assert "Feed connection error" in result["error"]
    assert result["total_packages"] == 0
    mock_registry_service.close.assert_called_once()