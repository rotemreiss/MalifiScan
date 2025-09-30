"""Test cases for proactive security use case."""

from unittest.mock import AsyncMock

import pytest

from src.core.usecases.proactive_security import ProactiveSecurityUseCase


@pytest.fixture
def mock_registry_service():
    """Mock registry service specifically for proactive security tests."""
    mock = AsyncMock()
    mock.health_check.return_value = True
    mock.is_package_blocked.return_value = False
    mock.block_packages.return_value = [True]  # Success for one package
    mock.list_blocked_packages.return_value = []
    mock.unblock_packages.return_value = [True]  # Success for one package
    mock.close.return_value = None
    return mock


@pytest.fixture
def proactive_usecase(mock_packages_feed, mock_registry_service):
    """Proactive security use case with mocked dependencies."""
    return ProactiveSecurityUseCase(mock_packages_feed, mock_registry_service)


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_success(
    proactive_usecase,
    mock_packages_feed,
    mock_registry_service,
    test_malicious_packages,
):
    """Test successful proactive blocking of malicious packages."""
    # Arrange
    # Get only npm packages from test fixtures (first two are npm)
    npm_packages = [
        pkg for pkg in test_malicious_packages if pkg.ecosystem.lower() == "npm"
    ]
    mock_packages_feed.fetch_malicious_packages.return_value = npm_packages
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = False
    mock_registry_service.block_packages.return_value = [True] * len(
        npm_packages
    )  # Success for all packages

    progress_calls = []

    def progress_callback(message, current, total):
        progress_calls.append((message, current, total))

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm", limit=10, progress_callback=progress_callback
    )

    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2  # Two npm packages in test fixtures
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
        max_packages=10, hours=6
    )
    mock_registry_service.health_check.assert_called_once()
    assert mock_registry_service.is_package_blocked.call_count == 2
    assert (
        mock_registry_service.block_packages.call_count == 2
    )  # Called for each package individually
    mock_registry_service.close.assert_called_once()


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_no_packages(
    proactive_usecase, mock_packages_feed, mock_registry_service
):
    """Test proactive blocking when no malicious packages are found."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = []

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm"
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
    test_malicious_packages,
):
    """Test proactive blocking when registry is unhealthy."""
    # Arrange
    npm_packages = [
        pkg for pkg in test_malicious_packages if pkg.ecosystem.lower() == "npm"
    ]
    mock_packages_feed.fetch_malicious_packages.return_value = npm_packages
    mock_registry_service.health_check.return_value = False

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm"
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
    test_malicious_packages,
):
    """Test proactive blocking when packages are already blocked."""
    # Arrange
    npm_packages = [
        pkg for pkg in test_malicious_packages if pkg.ecosystem.lower() == "npm"
    ]
    mock_packages_feed.fetch_malicious_packages.return_value = npm_packages
    mock_registry_service.health_check.return_value = True
    mock_registry_service.is_package_blocked.return_value = True  # Already blocked

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm"
    )

    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2
    assert result["success_count"] == 0
    assert result["already_blocked_count"] == 2
    assert len(result["blocked_packages"]) == 0
    assert len(result["already_blocked"]) == 2

    # Should not attempt to block if already blocked
    mock_registry_service.block_packages.assert_not_called()


@pytest.mark.asyncio
async def test_block_recent_malicious_packages_mixed_results(
    proactive_usecase,
    mock_packages_feed,
    mock_registry_service,
    test_malicious_packages,
):
    """Test proactive blocking with mixed success/failure results."""
    # Arrange
    npm_packages = [
        pkg for pkg in test_malicious_packages if pkg.ecosystem.lower() == "npm"
    ]
    mock_packages_feed.fetch_malicious_packages.return_value = npm_packages
    mock_registry_service.health_check.return_value = True

    # First package: not blocked, successful block
    # Second package: not blocked, failed block
    mock_registry_service.is_package_blocked.side_effect = [False, False]
    mock_registry_service.block_packages.side_effect = [
        True,
        False,
    ]  # First call succeeds, second call fails

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm"
    )

    # Assert
    assert result["success"] is True
    assert result["total_packages"] == 2
    assert result["success_count"] == 1  # Only one package was successfully blocked
    assert result["already_blocked_count"] == 0
    assert result["error_count"] == 1  # One package failed
    assert len(result["blocked_packages"]) == 1
    assert len(result["already_blocked"]) == 0
    assert len(result["errors"]) == 1

    # Verify the correct calls were made
    assert mock_registry_service.block_packages.call_count == 2  # Once for each package


@pytest.mark.asyncio
async def test_unblock_packages_by_criteria_dry_run(
    proactive_usecase, mock_registry_service
):
    """Test bulk unblocking in dry run mode."""
    # Arrange
    blocked_packages = [
        {"name": "evil-package-1", "pattern": "evil-package-1/*"},
        {"name": "evil-package-2", "pattern": "evil-package-2/*"},
        {"name": "good-package", "pattern": "good-package/*"},
    ]
    mock_registry_service.list_blocked_packages.return_value = blocked_packages

    # Act
    result = await proactive_usecase.unblock_packages_by_criteria(
        ecosystem="npm", package_pattern="evil-*", dry_run=True
    )

    # Assert
    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["total_blocked"] == 3
    assert len(result["matching_packages"]) == 2  # Only evil-* packages
    assert len(result["unblocked_packages"]) == 0  # Dry run
    assert "Would unblock 2 packages" in result["message"]

    # Should not actually unblock anything
    mock_registry_service.unblock_packages.assert_not_called()


@pytest.mark.asyncio
async def test_unblock_packages_by_criteria_actual_run(
    proactive_usecase, mock_registry_service
):
    """Test bulk unblocking in actual mode."""
    # Arrange
    blocked_packages = [
        {"name": "evil-package-1", "pattern": "evil-package-1/*"},
        {"name": "evil-package-2", "pattern": "evil-package-2/*"},
    ]
    mock_registry_service.list_blocked_packages.return_value = blocked_packages
    # Implementation calls unblock_packages once per matching package
    mock_registry_service.unblock_packages.side_effect = [
        [True],
        [True],
    ]  # Both calls succeed

    # Reset the mock to ensure the call count starts from 0
    mock_registry_service.unblock_packages.reset_mock()

    # Act
    result = await proactive_usecase.unblock_packages_by_criteria(
        ecosystem="npm", package_pattern="evil-*", dry_run=False
    )

    # Assert
    assert result["success"] is True
    assert result["dry_run"] is False
    assert result["total_blocked"] == 2
    assert result["unblocked_count"] == 2
    assert result["error_count"] == 0
    assert len(result["unblocked_packages"]) == 2

    # Should attempt to unblock each matching package individually
    assert (
        mock_registry_service.unblock_packages.call_count == 2
    )  # Called once per matching package


@pytest.mark.asyncio
async def test_exception_handling(
    proactive_usecase, mock_packages_feed, mock_registry_service
):
    """Test exception handling in proactive security operations."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.side_effect = Exception(
        "Feed connection error"
    )

    # Act
    result = await proactive_usecase.block_recent_malicious_packages(
        hours=6, ecosystem="npm"
    )

    # Assert
    assert result["success"] is False
    assert "Feed connection error" in result["error"]
    assert result["total_packages"] == 0
    mock_registry_service.close.assert_called_once()
