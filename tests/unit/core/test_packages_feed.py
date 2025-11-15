"""Tests for packages feed interface and implementations."""

from datetime import datetime
from typing import List, Optional

import pytest

from src.core.entities import MaliciousPackage
from src.core.interfaces.packages_feed import PackagesFeed


class MockPackagesFeed(PackagesFeed):
    """Mock implementation of PackagesFeed for testing."""

    def __init__(self):
        self.packages = []
        self.healthy = True
        self.fetch_call_count = 0
        self.health_check_call_count = 0
        self.should_raise_error = False
        self.error_message = "Mock error"

    async def fetch_malicious_packages(
        self,
        max_packages: Optional[int] = None,
        hours: Optional[int] = None,
        ecosystems: Optional[List[str]] = None,
    ) -> List[MaliciousPackage]:
        """Mock implementation of fetch_malicious_packages."""
        self.fetch_call_count += 1

        if self.should_raise_error:
            raise Exception(self.error_message)

        # Apply max_packages filter if specified
        packages = self.packages
        if max_packages is not None:
            packages = packages[:max_packages]

        # Filter by ecosystems if specified
        if ecosystems is not None:
            packages = [p for p in packages if p.ecosystem in ecosystems]

        # In a real implementation, hours would filter by modification time
        # For testing, we'll just return the filtered packages
        return packages

    async def get_available_ecosystems(self) -> List[str]:
        """Mock implementation of get_available_ecosystems."""
        if self.should_raise_error:
            raise Exception(self.error_message)

        # Return ecosystems from packages in the mock
        ecosystems = list(set(package.ecosystem for package in self.packages))
        return ecosystems

    async def health_check(self) -> bool:
        """Mock implementation of health_check."""
        self.health_check_call_count += 1

        if self.should_raise_error:
            raise Exception(self.error_message)

        return self.healthy

    def get_cache_stats(self) -> dict:
        """Mock implementation of get_cache_stats."""
        return {
            "total_packages": len(self.packages),
            "backend": "mock",
            "cache_enabled": False,
        }


class TestPackagesFeedInterface:
    """Test cases for PackagesFeed interface."""

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
                modified_at=datetime(2023, 1, 2, 12, 0, 0),
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
                affected_versions=["2.1.0", "2.1.1"],
                database_specific={"severity": "CRITICAL"},
                published_at=datetime(2023, 2, 1, 12, 0, 0),
                modified_at=datetime(2023, 2, 2, 12, 0, 0),
            ),
            MaliciousPackage(
                name="malicious-pkg-3",
                version="0.5.0",
                ecosystem="Maven",
                package_url="pkg:maven/com.example/malicious-pkg-3@0.5.0",
                advisory_id="OSV-2023-0003",
                summary="Third malicious package",
                details="Contains data exfiltration code",
                aliases=["CVE-2023-9999"],
                affected_versions=["0.5.0"],
                database_specific={"severity": "MEDIUM"},
                published_at=datetime(2023, 3, 1, 12, 0, 0),
                modified_at=datetime(2023, 3, 2, 12, 0, 0),
            ),
        ]

    @pytest.fixture
    def mock_feed(self, sample_packages):
        """Create a mock packages feed with sample data."""
        feed = MockPackagesFeed()
        feed.packages = sample_packages
        return feed

    def test_mock_feed_initialization(self):
        """Test mock feed initialization."""
        feed = MockPackagesFeed()

        assert feed.packages == []
        assert feed.healthy is True
        assert feed.fetch_call_count == 0
        assert feed.health_check_call_count == 0
        assert feed.should_raise_error is False

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_all(self, mock_feed, sample_packages):
        """Test fetching all malicious packages."""
        result = await mock_feed.fetch_malicious_packages()

        assert len(result) == 3
        assert result == sample_packages
        assert mock_feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_with_max_limit(
        self, mock_feed, sample_packages
    ):
        """Test fetching malicious packages with max limit."""
        result = await mock_feed.fetch_malicious_packages(max_packages=2)

        assert len(result) == 2
        assert result == sample_packages[:2]
        assert mock_feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_with_zero_limit(self, mock_feed):
        """Test fetching malicious packages with zero limit."""
        result = await mock_feed.fetch_malicious_packages(max_packages=0)

        assert len(result) == 0
        assert mock_feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_with_hours_parameter(
        self, mock_feed, sample_packages
    ):
        """Test fetching malicious packages with hours parameter."""
        # Hours parameter is passed but in our mock it doesn't filter
        # In real implementation this would filter by modification time
        result = await mock_feed.fetch_malicious_packages(hours=24)

        assert len(result) == 3
        assert result == sample_packages
        assert mock_feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_empty_feed(self):
        """Test fetching from empty feed."""
        feed = MockPackagesFeed()  # No packages

        result = await feed.fetch_malicious_packages()

        assert len(result) == 0
        assert feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_error(self, mock_feed):
        """Test fetching malicious packages when error occurs."""
        mock_feed.should_raise_error = True
        mock_feed.error_message = "Feed connection failed"

        with pytest.raises(Exception, match="Feed connection failed"):
            await mock_feed.fetch_malicious_packages()

        assert mock_feed.fetch_call_count == 1

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_feed):
        """Test health check when service is healthy."""
        result = await mock_feed.health_check()

        assert result is True
        assert mock_feed.health_check_call_count == 1

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_feed):
        """Test health check when service is unhealthy."""
        mock_feed.healthy = False

        result = await mock_feed.health_check()

        assert result is False
        assert mock_feed.health_check_call_count == 1

    @pytest.mark.asyncio
    async def test_health_check_error(self, mock_feed):
        """Test health check when error occurs."""
        mock_feed.should_raise_error = True
        mock_feed.error_message = "Health check failed"

        with pytest.raises(Exception, match="Health check failed"):
            await mock_feed.health_check()

        assert mock_feed.health_check_call_count == 1

    @pytest.mark.asyncio
    async def test_multiple_calls_increment_counters(self, mock_feed):
        """Test that multiple calls increment counters correctly."""
        # Multiple fetch calls
        await mock_feed.fetch_malicious_packages()
        await mock_feed.fetch_malicious_packages(max_packages=1)
        await mock_feed.fetch_malicious_packages(hours=12)

        # Multiple health check calls
        await mock_feed.health_check()
        await mock_feed.health_check()

        assert mock_feed.fetch_call_count == 3
        assert mock_feed.health_check_call_count == 2

    @pytest.mark.asyncio
    async def test_interface_contract_compliance(self, mock_feed):
        """Test that mock implementation complies with interface contract."""
        # Verify it's an instance of the interface
        assert isinstance(mock_feed, PackagesFeed)

        # Verify methods exist and are callable
        assert hasattr(mock_feed, "fetch_malicious_packages")
        assert hasattr(mock_feed, "health_check")
        assert callable(mock_feed.fetch_malicious_packages)
        assert callable(mock_feed.health_check)

        # Verify method signatures by calling with different parameter combinations
        result1 = await mock_feed.fetch_malicious_packages()
        result2 = await mock_feed.fetch_malicious_packages(max_packages=5)
        result3 = await mock_feed.fetch_malicious_packages(hours=24)
        result4 = await mock_feed.fetch_malicious_packages(max_packages=2, hours=12)

        # All should return lists
        assert isinstance(result1, list)
        assert isinstance(result2, list)
        assert isinstance(result3, list)
        assert isinstance(result4, list)

        # Health check should return boolean
        health_result = await mock_feed.health_check()
        assert isinstance(health_result, bool)

    def test_interface_is_abstract(self):
        """Test that PackagesFeed interface cannot be instantiated directly."""
        with pytest.raises(TypeError):
            PackagesFeed()

    @pytest.mark.asyncio
    async def test_concurrent_calls(self, mock_feed):
        """Test concurrent calls to the interface methods."""
        import asyncio

        # Create multiple concurrent tasks
        tasks = [
            mock_feed.fetch_malicious_packages(),
            mock_feed.fetch_malicious_packages(max_packages=1),
            mock_feed.health_check(),
            mock_feed.health_check(),
        ]

        results = await asyncio.gather(*tasks)

        # Verify results
        assert len(results) == 4
        assert isinstance(results[0], list)  # fetch result
        assert isinstance(results[1], list)  # fetch with limit result
        assert isinstance(results[2], bool)  # health check result
        assert isinstance(results[3], bool)  # health check result

        # Verify call counters
        assert mock_feed.fetch_call_count == 2
        assert mock_feed.health_check_call_count == 2
