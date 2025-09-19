"""Tests for security scanner use case."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from src.core.usecases.security_scanner import SecurityScanner
from src.core.entities import ScanStatus, MaliciousPackage, ScanResult, NotificationEvent, NotificationLevel, NotificationChannel


@pytest.fixture
def sample_malicious_package():
    """Create a sample malicious package for testing."""
    return MaliciousPackage(
        name="malicious-pkg",
        version="1.0.0",
        ecosystem="PyPI",
        package_url="pkg:pypi/malicious-pkg@1.0.0",
        advisory_id="OSV-2023-0001",
        summary="Malicious package with backdoor",
        details="This package contains a backdoor that steals credentials",
        aliases=["CVE-2023-1234"],
        affected_versions=["1.0.0", "1.0.1"],
        database_specific={"severity": "HIGH"},
        published_at=datetime(2023, 1, 1, 12, 0, 0),
        modified_at=datetime(2023, 1, 2, 12, 0, 0)
    )


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result for testing."""
    return ScanResult(
        scan_id="test-scan-001",
        timestamp=datetime(2023, 1, 1, 12, 0, 0),
        status=ScanStatus.SUCCESS,
        packages_scanned=100,
        malicious_packages_found=[],
        packages_blocked=[],
        malicious_packages_list=[],
        errors=[],
        execution_duration_seconds=30.5
    )


@pytest.fixture
def sample_notification_event(sample_scan_result):
    """Create a sample notification event for testing."""
    return NotificationEvent(
        event_id="notif-001",
        timestamp=datetime(2023, 1, 1, 12, 0, 0),
        level=NotificationLevel.CRITICAL,
        title="Malicious Package Detected",
        message="Found malicious package: malicious-pkg@1.0.0",
        scan_result=sample_scan_result,
        affected_packages=[],
        recommended_actions=["Block package", "Review dependencies"],
        channels=[NotificationChannel.EMAIL],
        metadata={"package": "malicious-pkg", "version": "1.0.0"}
    )


@pytest.fixture
def mock_packages_feed():
    """Mock packages feed service."""
    mock = AsyncMock()
    mock.fetch_malicious_packages.return_value = []
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_packages_registry():
    """Mock packages registry service."""
    mock = AsyncMock()
    mock.check_existing_packages.return_value = []
    mock.block_packages.return_value = []
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_notification_service():
    """Mock notification service."""
    mock = AsyncMock()
    mock.send_notification.return_value = None
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_storage_service():
    """Mock storage service."""
    mock = AsyncMock()
    mock.store_scan_result.return_value = None
    mock.get_scan_history.return_value = []
    mock.health_check.return_value = True
    return mock


class TestSecurityScanner:
    """Tests for SecurityScanner use case."""
    
    @pytest.fixture
    def security_scanner(self, mock_packages_feed, mock_packages_registry, 
                        mock_notification_service, mock_storage_service):
        """Create a security scanner with mocked dependencies."""
        return SecurityScanner(
            packages_feed=mock_packages_feed,
            registry_service=mock_packages_registry,
            notification_service=mock_notification_service,
            storage_service=mock_storage_service
        )
    
    @pytest.mark.asyncio
    async def test_execute_scan_success_no_new_packages(self, security_scanner, 
                                                        mock_packages_feed,
                                                        mock_packages_registry,
                                                        mock_storage_service,
                                                        sample_malicious_package):
        """Test successful scan with no new packages."""
        # Setup mocks
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.return_value = [sample_malicious_package]
        mock_packages_registry.block_packages.return_value = []
        
        # Execute scan
        result = await security_scanner.execute_scan()
        
        # Verify result
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 1
        assert len(result.malicious_packages_found) == 1
        assert len(result.packages_blocked) == 0
        assert len(result.malicious_packages_list) == 1
        assert result.is_successful
        assert not result.has_new_threats
        
        # Verify mock calls
        mock_packages_feed.fetch_malicious_packages.assert_called_once()
        mock_packages_registry.check_existing_packages.assert_called_once()
        mock_packages_registry.block_packages.assert_not_called()
        mock_storage_service.store_scan_result.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_scan_success_with_new_packages(self, security_scanner,
                                                         mock_packages_feed,
                                                         mock_packages_registry,
                                                         mock_storage_service,
                                                         sample_malicious_package):
        """Test successful scan with new packages to block."""
        # Setup mocks
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = [sample_malicious_package.package_identifier]
        
        # Execute scan
        result = await security_scanner.execute_scan()
        
        # Verify result
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 1
        assert len(result.malicious_packages_found) == 1
        assert len(result.packages_blocked) == 1
        assert len(result.malicious_packages_list) == 0
        assert result.is_successful
        assert result.has_new_threats
        assert result.new_threats_count == 1
        
        # Verify mock calls
        mock_packages_registry.block_packages.assert_called_once_with([sample_malicious_package])
    
    @pytest.mark.asyncio
    async def test_execute_scan_feed_failure(self, security_scanner, mock_packages_feed):
        """Test scan failure when feed is unavailable."""
        # Setup mock to raise exception
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed unavailable")
        
        # Execute scan and expect exception
        with pytest.raises(Exception, match="Scan failed"):
            await security_scanner.execute_scan()
    
    @pytest.mark.asyncio
    async def test_execute_scan_registry_failure(self, security_scanner,
                                                mock_packages_feed,
                                                mock_packages_registry,
                                                sample_malicious_package):
        """Test scan handling registry failure."""
        # Setup mocks
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.side_effect = Exception("Registry unavailable")
        
        # Execute scan and expect exception
        with pytest.raises(Exception, match="Scan failed"):
            await security_scanner.execute_scan()
    
    @pytest.mark.asyncio
    async def test_execute_scan_storage_failure(self, security_scanner,
                                               mock_packages_feed,
                                               mock_packages_registry,
                                               mock_storage_service,
                                               sample_malicious_package):
        """Test scan handling storage failure (should not fail entire scan)."""
        # Setup mocks
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = [sample_malicious_package.package_identifier]
        mock_storage_service.store_scan_result.side_effect = Exception("Storage unavailable")
        
        # Execute scan - should complete despite storage failure
        result = await security_scanner.execute_scan()
        
        # Verify result
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful
        # Errors should be recorded
        assert any("Storage error" in error for error in result.errors)
    
    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, security_scanner,
                                           mock_packages_feed,
                                           mock_packages_registry,
                                           mock_notification_service,
                                           mock_storage_service):
        """Test health check when all services are healthy."""
        # All mocks return True by default
        
        health_status = await security_scanner.health_check()
        
        assert health_status["packages_feed"] is True
        assert health_status["registry_service"] is True
        assert health_status["notification_service"] is True
        assert health_status["storage_service"] is True
        assert health_status["overall"] is True
    
    @pytest.mark.asyncio
    async def test_health_check_some_unhealthy(self, security_scanner,
                                              mock_packages_feed,
                                              mock_packages_registry,
                                              mock_notification_service,
                                              mock_storage_service):
        """Test health check when some services are unhealthy."""
        # Make some services unhealthy
        mock_packages_feed.health_check.return_value = False
        mock_notification_service.health_check.side_effect = Exception("Service down")
        
        health_status = await security_scanner.health_check()
        
        assert health_status["packages_feed"] is False
        assert health_status["registry_service"] is True
        assert health_status["notification_service"] is False
        assert health_status["storage_service"] is True
        assert health_status["overall"] is False
    
    @pytest.mark.asyncio
    async def test_notification_failure_does_not_fail_scan(self, security_scanner,
                                                          mock_packages_feed,
                                                          mock_packages_registry,
                                                          mock_notification_service,
                                                          sample_malicious_package):
        """Test that notification failure doesn't fail the entire scan."""
        # Setup mocks
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = [sample_malicious_package.package_identifier]
        mock_notification_service.send_notification.side_effect = Exception("Notification failed")
        
        # Execute scan - should complete despite notification failure
        result = await security_scanner.execute_scan()
        
        # Verify result
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful