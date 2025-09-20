"""Test cases for feed management use case."""

import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timezone

from src.core.entities.malicious_package import MaliciousPackage
from src.core.usecases.feed_management import FeedManagementUseCase


@pytest.fixture
def mock_packages_feed():
    """Mock packages feed for testing."""
    feed = AsyncMock()
    feed.name = "Test OSV Feed"
    return feed


@pytest.fixture
def feed_usecase(mock_packages_feed):
    """Feed management use case with mocked dependencies."""
    return FeedManagementUseCase(mock_packages_feed)


@pytest.fixture
def sample_packages():
    """Sample malicious packages for testing."""
    return [
        MaliciousPackage(
            advisory_id="OSV-2023-001",
            name="evil-npm-package",
            ecosystem="npm",
            version="1.0.0",
            package_url="https://example.com/evil-npm-package",
            summary="A malicious npm package",
            details="Detailed description of the malicious package",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        ),
        MaliciousPackage(
            advisory_id="OSV-2023-002",
            name="malicious-pypi-package",
            ecosystem="pypi",
            version="2.0.0",
            package_url="https://example.com/malicious-pypi-package",
            summary="A malicious pypi package",
            details="Detailed description of the malicious pypi package",
            aliases=[],
            affected_versions=["2.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        ),
        MaliciousPackage(
            advisory_id="OSV-2023-003",
            name="another-npm-package",
            ecosystem="npm",
            version="1.5.0",
            package_url="https://example.com/another-npm-package",
            summary="Another malicious npm package",
            details="Detailed description of another malicious npm package",
            aliases=[],
            affected_versions=["1.5.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
    ]


@pytest.mark.asyncio
async def test_fetch_recent_packages_success(feed_usecase, mock_packages_feed, sample_packages):
    """Test successful fetching of recent packages."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_packages
    
    # Act
    result = await feed_usecase.fetch_recent_packages(ecosystem="npm", limit=100, hours=48)
    
    # Assert
    assert result["success"] is True
    assert result["total_count"] == 2  # Only npm packages
    assert result["ecosystem_filter"] == "npm"
    assert result["hours_filter"] == 48
    assert result["limit"] == 100
    assert "npm" in result["ecosystem_counts"]
    assert result["ecosystem_counts"]["npm"] == 2
    assert isinstance(result["fetch_time"], datetime)
    
    # Verify the call
    mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
        max_packages=100,
        hours=48
    )


@pytest.mark.asyncio
async def test_fetch_recent_packages_no_ecosystem_filter(feed_usecase, mock_packages_feed, sample_packages):
    """Test fetching packages without ecosystem filter."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_packages
    
    # Act
    result = await feed_usecase.fetch_recent_packages(limit=50, hours=24)
    
    # Assert
    assert result["success"] is True
    assert result["total_count"] == 3  # All packages
    assert result["ecosystem_filter"] is None
    assert result["ecosystem_counts"]["npm"] == 2
    assert result["ecosystem_counts"]["pypi"] == 1


@pytest.mark.asyncio
async def test_fetch_recent_packages_empty_result(feed_usecase, mock_packages_feed):
    """Test fetching packages when none are found."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = []
    
    # Act
    result = await feed_usecase.fetch_recent_packages(ecosystem="maven", limit=10, hours=6)
    
    # Assert
    assert result["success"] is True
    assert result["total_count"] == 0
    assert result["packages"] == []
    assert result["ecosystem_counts"] == {}


@pytest.mark.asyncio
async def test_fetch_recent_packages_exception(feed_usecase, mock_packages_feed):
    """Test exception handling during package fetching."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed connection error")
    
    # Act
    result = await feed_usecase.fetch_recent_packages(ecosystem="npm", limit=100, hours=48)
    
    # Assert
    assert result["success"] is False
    assert "Feed connection error" in result["error"]
    assert result["total_count"] == 0
    assert result["packages"] == []


@pytest.mark.asyncio
async def test_get_feed_health_success(feed_usecase, mock_packages_feed, sample_packages):
    """Test successful feed health check."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_packages[:1]
    
    # Act
    result = await feed_usecase.get_feed_health()
    
    # Assert
    assert result["success"] is True
    assert result["healthy"] is True
    assert result["feed_name"] == "Test OSV Feed"
    assert result["test_fetch_count"] == 1
    
    # Verify the test call
    mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
        max_packages=1,
        hours=24
    )


@pytest.mark.asyncio
async def test_get_feed_health_unhealthy(feed_usecase, mock_packages_feed):
    """Test feed health check when feed is unhealthy."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = None
    
    # Act
    result = await feed_usecase.get_feed_health()
    
    # Assert
    assert result["success"] is True
    assert result["healthy"] is False
    assert result["test_fetch_count"] == 0


@pytest.mark.asyncio
async def test_get_feed_health_exception(feed_usecase, mock_packages_feed):
    """Test feed health check with exception."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Network error")
    
    # Act
    result = await feed_usecase.get_feed_health()
    
    # Assert
    assert result["success"] is False
    assert "Network error" in result["error"]
    assert result["healthy"] is False


@pytest.mark.asyncio
async def test_get_package_details_found(feed_usecase, mock_packages_feed, sample_packages):
    """Test getting details for a specific package that exists."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_packages
    
    # Act
    result = await feed_usecase.get_package_details("evil-npm-package", "npm")
    
    # Assert
    assert result["success"] is True
    assert result["found"] is True
    assert result["package_name"] == "evil-npm-package"
    assert result["ecosystem"] == "npm"
    assert result["count"] == 1
    assert len(result["packages"]) == 1
    assert result["packages"][0].name == "evil-npm-package"


@pytest.mark.asyncio
async def test_get_package_details_not_found(feed_usecase, mock_packages_feed, sample_packages):
    """Test getting details for a package that doesn't exist."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.return_value = sample_packages
    
    # Act
    result = await feed_usecase.get_package_details("nonexistent-package", "npm")
    
    # Assert
    assert result["success"] is True
    assert result["found"] is False
    assert result["package_name"] == "nonexistent-package"
    assert result["ecosystem"] == "npm"
    assert result["packages"] == []


@pytest.mark.asyncio
async def test_get_package_details_exception(feed_usecase, mock_packages_feed):
    """Test exception handling in get_package_details."""
    # Arrange
    mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed error")
    
    # Act
    result = await feed_usecase.get_package_details("test-package", "npm")
    
    # Assert
    assert result["success"] is False
    assert "Feed error" in result["error"]
    assert result["found"] is False