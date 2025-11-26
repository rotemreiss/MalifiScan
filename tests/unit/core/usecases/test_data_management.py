"""Tests for data management use case."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from src.core.entities.malicious_package import MaliciousPackage
from src.core.entities.scan_result import ScanResult, ScanStatus
from src.core.usecases.data_management import DataManagementUseCase


class TestDataManagementUseCase:
    """Test suite for DataManagementUseCase."""

    @pytest.fixture
    def mock_storage_service(self):
        """Mock storage service."""
        return AsyncMock()

    @pytest.fixture
    def mock_packages_feed(self):
        """Mock packages feed."""
        return AsyncMock()

    @pytest.fixture
    def sample_malicious_packages(self):
        """Create sample malicious packages for testing."""
        now = datetime.now()
        old_time = now - timedelta(hours=72)
        recent_time = now - timedelta(hours=24)

        return [
            MaliciousPackage(
                name="evil-package-1",
                version="1.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/evil-package-1@1.0.0",
                advisory_id="OSV-2023-0001",
                summary="Evil package 1",
                details="Malicious package 1",
                aliases=["CVE-2023-1001"],
                affected_versions=["1.0.0"],
                database_specific={"severity": "HIGH"},
                published_at=old_time,
                modified_at=recent_time,
            ),
            MaliciousPackage(
                name="evil-package-2",
                version="2.0.0",
                ecosystem="npm",
                package_url="pkg:npm/evil-package-2@2.0.0",
                advisory_id="OSV-2023-0002",
                summary="Evil package 2",
                details="Malicious package 2",
                aliases=["CVE-2023-1002"],
                affected_versions=["2.0.0"],
                database_specific={"severity": "MEDIUM"},
                published_at=old_time,
                modified_at=old_time,
            ),
            MaliciousPackage(
                name="evil-package-3",
                version="3.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/evil-package-3@3.0.0",
                advisory_id="OSV-2023-0003",
                summary="Evil package 3",
                details="Malicious package 3",
                aliases=["CVE-2023-1003"],
                affected_versions=["3.0.0"],
                database_specific={"severity": "LOW"},
                published_at=recent_time,
                modified_at=recent_time,
            ),
        ]

    @pytest.fixture
    def sample_scan_results(self):
        """Create sample scan results for testing."""
        return [
            ScanResult(
                scan_id="scan-001",
                timestamp=datetime.now(),
                status=ScanStatus.SUCCESS,
                packages_scanned=100,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=30.5,
            ),
            ScanResult(
                scan_id="scan-002",
                timestamp=datetime.now() - timedelta(hours=1),
                status=ScanStatus.SUCCESS,
                packages_scanned=150,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=45.2,
            ),
        ]

    @pytest.fixture
    def data_management_use_case(self, mock_storage_service, mock_packages_feed):
        """Create data management use case with mocked dependencies."""
        return DataManagementUseCase(
            storage_service=mock_storage_service, packages_feed=mock_packages_feed
        )

    def test_init(self, mock_storage_service, mock_packages_feed):
        """Test data management use case initialization."""
        use_case = DataManagementUseCase(mock_storage_service, mock_packages_feed)

        assert use_case.storage_service == mock_storage_service
        assert use_case.packages_feed == mock_packages_feed
        assert use_case.logger is not None

    @pytest.mark.asyncio
    async def test_fetch_osv_packages_success(
        self, data_management_use_case, mock_packages_feed, sample_malicious_packages
    ):
        """Test successful fetching of OSV packages."""
        mock_packages_feed.fetch_malicious_packages.return_value = (
            sample_malicious_packages
        )

        result = await data_management_use_case.fetch_osv_packages()

        assert result["success"] is True
        assert len(result["packages"]) == 3
        assert result["total_packages"] == 3
        assert result["ecosystems"] == {"PyPI": 2, "npm": 1}
        assert result["filter_info"]["limit"] is None
        assert result["filter_info"]["hours"] == 48
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=None, hours=48, ecosystems=None
        )

    @pytest.mark.asyncio
    async def test_fetch_osv_packages_with_ecosystem_filter(
        self, data_management_use_case, mock_packages_feed, sample_malicious_packages
    ):
        """Test fetching OSV packages with ecosystem filter."""
        # Mock should return only the requested ecosystem's packages
        npm_packages = [
            pkg for pkg in sample_malicious_packages if pkg.ecosystem == "npm"
        ]
        mock_packages_feed.fetch_malicious_packages.return_value = npm_packages

        result = await data_management_use_case.fetch_osv_packages(ecosystem="npm")

        assert result["success"] is True
        assert len(result["packages"]) == 1
        assert result["total_packages"] == 1
        assert result["ecosystems"] == {"npm": 1}
        assert result["filter_info"]["ecosystem"] == "npm"

        # Verify the feed was called with ecosystem filter
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=None, hours=48, ecosystems=["npm"]
        )

        # Verify only npm packages are returned
        for pkg in result["packages"]:
            assert pkg.ecosystem == "npm"

    @pytest.mark.asyncio
    async def test_fetch_osv_packages_with_custom_params(
        self, data_management_use_case, mock_packages_feed, sample_malicious_packages
    ):
        """Test fetching OSV packages with custom parameters."""
        # Mock should return only the requested ecosystem's packages
        pypi_packages = [
            pkg for pkg in sample_malicious_packages if pkg.ecosystem == "PyPI"
        ]
        mock_packages_feed.fetch_malicious_packages.return_value = pypi_packages

        result = await data_management_use_case.fetch_osv_packages(
            ecosystem="PyPI", limit=50, hours=24
        )

        assert result["success"] is True
        assert result["filter_info"]["ecosystem"] == "PyPI"
        assert result["filter_info"]["limit"] == 50
        assert result["filter_info"]["hours"] == 24
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=50, hours=24, ecosystems=["PyPI"]
        )

    @pytest.mark.asyncio
    async def test_fetch_osv_packages_feed_error(
        self, data_management_use_case, mock_packages_feed
    ):
        """Test fetching when packages feed fails."""
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception(
            "Feed error"
        )

        result = await data_management_use_case.fetch_osv_packages()

        assert result["success"] is False
        assert "Feed error" in result["error"]
        assert result["packages"] == []
        assert result["total_packages"] == 0
        assert result["ecosystems"] == {}

    @pytest.mark.asyncio
    async def test_fetch_osv_packages_case_insensitive_ecosystem(
        self, data_management_use_case, mock_packages_feed, sample_malicious_packages
    ):
        """Test that OSV ecosystem filtering is case insensitive."""
        # Mock should return only npm packages (ecosystem filter is handled by feed now)
        npm_packages = [
            pkg for pkg in sample_malicious_packages if pkg.ecosystem == "npm"
        ]
        mock_packages_feed.fetch_malicious_packages.return_value = npm_packages

        result = await data_management_use_case.fetch_osv_packages(ecosystem="NPM")

        assert result["success"] is True
        assert result["total_packages"] == 1

        # Verify the feed was called with the ecosystem (feed handles case sensitivity)
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=None, hours=48, ecosystems=["NPM"]
        )

        # Should match "npm" packages despite uppercase input
        for pkg in result["packages"]:
            assert pkg.ecosystem == "npm"
