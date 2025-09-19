"""Tests for scan results use case."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from src.core.usecases.scan_results import ScanResultsManager, ScanSummary, DetailedScanResult
from src.core.entities import ScanResult, ScanStatus, MaliciousPackage


@pytest.fixture
def mock_storage_service():
    """Create a mock storage service."""
    return AsyncMock()


@pytest.fixture
def mock_registry_service():
    """Create a mock registry service."""
    mock = AsyncMock()
    mock.get_registry_name.return_value = "JFrog"
    return mock


@pytest.fixture
def scan_results_manager(mock_storage_service, mock_registry_service):
    """Create a scan results manager with mocked dependencies."""
    return ScanResultsManager(mock_storage_service, mock_registry_service)


@pytest.fixture
def sample_malicious_package():
    """Create a sample malicious package."""
    return MaliciousPackage(
        name="test-package",
        version="1.0.0",
        ecosystem="npm",
        package_url="pkg:npm/test-package@1.0.0",
        advisory_id="TEST-001",
        summary="Test malicious package",
        details="This is a test package",
        aliases=["alias1"],
        affected_versions=["1.0.0", "1.0.1"],
        database_specific={"severity": "high"},
        published_at=datetime.now(timezone.utc),
        modified_at=datetime.now(timezone.utc)
    )


@pytest.fixture
def sample_scan_result(sample_malicious_package):
    """Create a sample scan result."""
    return ScanResult(
        scan_id="test-scan-123",
        timestamp=datetime.now(timezone.utc),
        status=ScanStatus.SUCCESS,
        packages_scanned=10,
        malicious_packages_found=[sample_malicious_package],
        packages_blocked=[],
        malicious_packages_list=[sample_malicious_package],
        errors=[],
        execution_duration_seconds=30.5
    )


class TestScanResultsManager:
    """Test cases for ScanResultsManager."""

    @pytest.mark.asyncio
    async def test_get_recent_scans_success(self, scan_results_manager, mock_storage_service, sample_scan_result):
        """Test successful retrieval of recent scans."""
        # Arrange
        mock_storage_service.get_scan_results.return_value = [sample_scan_result]
        scan_results_manager._get_findings_count_for_scan = AsyncMock(return_value=1)
        
        # Act
        result = await scan_results_manager.get_recent_scans(limit=3)
        
        # Assert
        assert len(result) == 1
        assert isinstance(result[0], ScanSummary)
        assert result[0].scan_id == "test-scan-123"
        assert result[0].packages_scanned == 10
        assert result[0].malicious_packages_found == 1
        assert result[0].findings_count == 1
        assert result[0].status == "success"
        mock_storage_service.get_scan_results.assert_called_once_with(limit=3)

    @pytest.mark.asyncio
    async def test_get_recent_scans_empty(self, scan_results_manager, mock_storage_service):
        """Test retrieval when no scans exist."""
        # Arrange
        mock_storage_service.get_scan_results.return_value = []
        
        # Act
        result = await scan_results_manager.get_recent_scans(limit=3)
        
        # Assert
        assert result == []
        mock_storage_service.get_scan_results.assert_called_once_with(limit=3)

    @pytest.mark.asyncio
    async def test_get_recent_scans_storage_error(self, scan_results_manager, mock_storage_service):
        """Test handling of storage errors during scan retrieval."""
        # Arrange
        mock_storage_service.get_scan_results.side_effect = Exception("Storage error")
        
        # Act & Assert
        with pytest.raises(RuntimeError, match="Failed to retrieve recent scans"):
            await scan_results_manager.get_recent_scans(limit=3)

    @pytest.mark.asyncio
    async def test_get_scan_details_success(self, scan_results_manager, mock_storage_service, sample_scan_result, sample_malicious_package):
        """Test successful retrieval of scan details."""
        # Arrange
        mock_storage_service.get_scan_results.return_value = [sample_scan_result]
        scan_results_manager._get_findings_for_scan = AsyncMock(return_value=[sample_malicious_package])
        
        # Act
        result = await scan_results_manager.get_scan_details("test-scan-123")
        
        # Assert
        assert result is not None
        assert isinstance(result, DetailedScanResult)
        assert result.scan_result.scan_id == "test-scan-123"
        assert len(result.findings) == 1
        assert result.findings[0].name == "test-package"
        mock_storage_service.get_scan_results.assert_called_once_with(scan_id="test-scan-123")

    @pytest.mark.asyncio
    async def test_get_scan_details_not_found(self, scan_results_manager, mock_storage_service):
        """Test retrieval when scan ID doesn't exist."""
        # Arrange
        mock_storage_service.get_scan_results.return_value = []
        
        # Act
        result = await scan_results_manager.get_scan_details("nonexistent-scan")
        
        # Assert
        assert result is None
        mock_storage_service.get_scan_results.assert_called_once_with(scan_id="nonexistent-scan")

    @pytest.mark.asyncio
    async def test_get_scan_details_storage_error(self, scan_results_manager, mock_storage_service):
        """Test handling of storage errors during scan detail retrieval."""
        # Arrange
        mock_storage_service.get_scan_results.side_effect = Exception("Storage error")
        
        # Act & Assert
        with pytest.raises(RuntimeError, match="Failed to retrieve scan details"):
            await scan_results_manager.get_scan_details("test-scan-123")

    @pytest.mark.asyncio
    async def test_analyze_scan_results_with_findings(self, scan_results_manager, sample_scan_result, sample_malicious_package):
        """Test analysis of scan results with findings."""
        # Arrange
        findings = [sample_malicious_package]
        
        # Act
        result = await scan_results_manager._analyze_scan_results(sample_scan_result, findings)
        
        # Assert
        assert "found_matches" in result
        assert "safe_packages" in result
        assert "not_found_count" in result
        assert result["not_found_count"] == 0  # 1 scanned, 1 found = 0 not found

    @pytest.mark.asyncio
    async def test_analyze_scan_results_no_findings(self, scan_results_manager, sample_scan_result):
        """Test analysis of scan results with no findings."""
        # Arrange
        findings = []
        
        # Act
        result = await scan_results_manager._analyze_scan_results(sample_scan_result, findings)
        
        # Assert
        assert result["found_matches"] == []
        assert result["safe_packages"] == []
        assert result["not_found_count"] == 1  # 1 scanned, 0 found = 1 not found


class TestScanSummary:
    """Test cases for ScanSummary dataclass."""

    def test_scan_summary_creation(self):
        """Test creating a scan summary."""
        timestamp = datetime.now(timezone.utc)
        summary = ScanSummary(
            scan_id="test-123",
            timestamp=timestamp,
            status="success",
            packages_scanned=10,
            malicious_packages_found=2,
            findings_count=1,
            execution_duration_seconds=15.5
        )
        
        assert summary.scan_id == "test-123"
        assert summary.timestamp == timestamp
        assert summary.status == "success"
        assert summary.packages_scanned == 10
        assert summary.malicious_packages_found == 2
        assert summary.findings_count == 1
        assert summary.execution_duration_seconds == 15.5


class TestDetailedScanResult:
    """Test cases for DetailedScanResult dataclass."""

    def test_detailed_scan_result_creation(self, sample_scan_result, sample_malicious_package):
        """Test creating a detailed scan result."""
        detailed = DetailedScanResult(
            scan_result=sample_scan_result,
            findings=[sample_malicious_package],
            found_matches=[],
            safe_packages=[],
            not_found_count=0
        )
        
        assert detailed.scan_result == sample_scan_result
        assert len(detailed.findings) == 1
        assert detailed.findings[0] == sample_malicious_package
        assert detailed.found_matches == []
        assert detailed.safe_packages == []
        assert detailed.not_found_count == 0