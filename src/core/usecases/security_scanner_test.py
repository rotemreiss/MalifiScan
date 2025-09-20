"""Tests for security scanner use case."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock, Mock
from datetime import datetime, timezone
import uuid

from src.core.usecases.security_scanner import SecurityScanner, SecurityScannerError
from src.core.entities import (
    ScanStatus, MaliciousPackage, ScanResult, NotificationEvent, 
    NotificationLevel, NotificationChannel
)


@pytest.fixture
def sample_malicious_packages():
    """Create multiple sample malicious packages for testing."""
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
            affected_versions=["2.1.0", "2.1.1"],
            database_specific={"severity": "CRITICAL"},
            published_at=datetime(2023, 2, 1, 12, 0, 0),
            modified_at=datetime(2023, 2, 2, 12, 0, 0)
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
            modified_at=datetime(2023, 3, 2, 12, 0, 0)
        )
    ]


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


    # Enhanced tests for better coverage
    @pytest.mark.asyncio
    async def test_execute_scan_empty_feed(self, security_scanner, 
                                          mock_packages_feed,
                                          mock_packages_registry,
                                          mock_storage_service):
        """Test scan execution when feed returns no packages."""
        # Feed returns empty list
        mock_packages_feed.fetch_malicious_packages.return_value = []
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 0
        assert len(result.malicious_packages_found) == 0
        assert len(result.packages_blocked) == 0
        assert len(result.malicious_packages_list) == 0
        assert result.is_successful
        assert not result.has_new_threats
        assert result.new_threats_count == 0
        
        # Verify service calls
        mock_packages_feed.fetch_malicious_packages.assert_called_once()
        mock_packages_registry.check_existing_packages.assert_called_once_with([])
        mock_packages_registry.block_packages.assert_not_called()
        mock_storage_service.store_scan_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_scan_mixed_scenarios(self, security_scanner,
                                               mock_packages_feed,
                                               mock_packages_registry,
                                               mock_storage_service,
                                               sample_malicious_packages):
        """Test scan with mixed scenarios - some new, some existing packages."""
        # Setup: 3 packages from feed, 1 already exists, 2 are new and get blocked
        all_packages = sample_malicious_packages
        existing_packages = [sample_malicious_packages[0]]  # First package already exists
        new_packages = sample_malicious_packages[1:]  # Last two are new
        blocked_identifiers = [pkg.package_identifier for pkg in new_packages]
        
        mock_packages_feed.fetch_malicious_packages.return_value = all_packages
        mock_packages_registry.check_existing_packages.return_value = existing_packages
        mock_packages_registry.block_packages.return_value = blocked_identifiers
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 3
        assert len(result.malicious_packages_found) == 3
        assert len(result.packages_blocked) == 2
        assert len(result.malicious_packages_list) == 1
        assert result.is_successful
        assert result.has_new_threats
        assert result.new_threats_count == 2
        
        # Verify the right packages were processed
        mock_packages_registry.block_packages.assert_called_once_with(new_packages)

    @pytest.mark.asyncio
    async def test_execute_scan_all_packages_already_exist(self, security_scanner,
                                                          mock_packages_feed,
                                                          mock_packages_registry,
                                                          sample_malicious_packages):
        """Test scan when all packages already exist in registry."""
        mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages
        mock_packages_registry.check_existing_packages.return_value = sample_malicious_packages
        mock_packages_registry.block_packages.return_value = []
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 3
        assert len(result.malicious_packages_found) == 3
        assert len(result.packages_blocked) == 0
        assert len(result.malicious_packages_list) == 3
        assert result.is_successful
        assert not result.has_new_threats
        assert result.new_threats_count == 0
        
        # Block packages should not be called
        mock_packages_registry.block_packages.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_scan_partial_blocking_failure(self, security_scanner,
                                                        mock_packages_feed,
                                                        mock_packages_registry,
                                                        sample_malicious_packages):
        """Test scan when some packages fail to be blocked."""
        new_packages = sample_malicious_packages
        # Only one package gets blocked successfully
        partially_blocked = [sample_malicious_packages[0].package_identifier]
        
        mock_packages_feed.fetch_malicious_packages.return_value = new_packages
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = partially_blocked
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 3
        assert len(result.malicious_packages_found) == 3
        assert len(result.packages_blocked) == 1  # Only one was blocked
        assert len(result.malicious_packages_list) == 0
        assert result.is_successful
        assert result.has_new_threats

    @pytest.mark.asyncio
    async def test_execute_scan_storage_service_both_operations_fail(self, security_scanner,
                                                                   mock_packages_feed,
                                                                   mock_packages_registry,
                                                                   mock_storage_service,
                                                                   sample_malicious_packages):
        """Test scan when both storage operations fail."""
        mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
        # Both storage operations fail
        mock_storage_service.store_scan_result.side_effect = Exception("Scan result storage failed")
        mock_storage_service.store_malicious_packages.side_effect = Exception("Package storage failed")
        
        result = await security_scanner.execute_scan()
        
        # Scan should still succeed despite storage failures
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful
        assert len(result.errors) >= 1  # Should contain storage error
        assert any("Storage error" in error for error in result.errors)

    @pytest.mark.asyncio
    async def test_execute_scan_with_logging(self, security_scanner,
                                           mock_packages_feed,
                                           mock_packages_registry,
                                           sample_malicious_packages):
        """Test scan execution with logging verification."""
        mock_packages_feed.fetch_malicious_packages.return_value = sample_malicious_packages
        mock_packages_registry.check_existing_packages.return_value = []
        mock_packages_registry.block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
        with patch('src.core.usecases.security_scanner.logger') as mock_logger:
            result = await security_scanner.execute_scan()
            
            # Verify logging calls
            assert mock_logger.info.call_count >= 5  # Should have multiple info logs
            mock_logger.info.assert_any_call(f"Starting security scan {result.scan_id}")
            mock_logger.info.assert_any_call("Fetching malicious packages from feed")
            mock_logger.info.assert_any_call(f"Found {len(sample_malicious_packages)} malicious packages in feed")
            mock_logger.info.assert_any_call("Checking for existing packages in registry")
            mock_logger.info.assert_any_call(f"Blocking {len(sample_malicious_packages)} new malicious packages")

    @pytest.mark.asyncio
    async def test_execute_scan_failed_scan_storage_attempt(self, security_scanner,
                                                           mock_packages_feed,
                                                           mock_storage_service):
        """Test that failed scan results are attempted to be stored."""
        # Make feed fail
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed connection failed")
        
        with pytest.raises(SecurityScannerError, match="Scan failed"):
            await security_scanner.execute_scan()
        
        # Verify that store_scan_result was called even for failed scan
        mock_storage_service.store_scan_result.assert_called_once()
        
        # Check that the stored result has FAILED status
        stored_result = mock_storage_service.store_scan_result.call_args[0][0]
        assert stored_result.status == ScanStatus.FAILED
        assert len(stored_result.errors) > 0

    @pytest.mark.asyncio
    async def test_execute_scan_failed_scan_storage_also_fails(self, security_scanner,
                                                              mock_packages_feed,
                                                              mock_storage_service):
        """Test when scan fails and storing the failed result also fails."""
        # Make feed fail
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed connection failed")
        # Make storage fail too
        mock_storage_service.store_scan_result.side_effect = Exception("Storage completely down")
        
        with patch('src.core.usecases.security_scanner.logger') as mock_logger:
            with pytest.raises(SecurityScannerError, match="Scan failed"):
                await security_scanner.execute_scan()
            
            # Should log the storage error
            mock_logger.error.assert_any_call("Failed to store failed scan result: Storage completely down")

    @pytest.mark.asyncio
    async def test_health_check_all_services_exception(self, security_scanner,
                                                      mock_packages_feed,
                                                      mock_packages_registry,
                                                      mock_notification_service,
                                                      mock_storage_service):
        """Test health check when all services raise exceptions."""
        # Make all services raise exceptions
        mock_packages_feed.health_check.side_effect = Exception("Feed service exception")
        mock_packages_registry.health_check.side_effect = Exception("Registry service exception")
        mock_notification_service.health_check.side_effect = Exception("Notification service exception")
        mock_storage_service.health_check.side_effect = Exception("Storage service exception")
        
        with patch('src.core.usecases.security_scanner.logger') as mock_logger:
            health_status = await security_scanner.health_check()
            
            assert health_status["packages_feed"] is False
            assert health_status["registry_service"] is False
            assert health_status["notification_service"] is False
            assert health_status["storage_service"] is False
            assert health_status["overall"] is False
            
            # Verify error logging
            assert mock_logger.error.call_count == 4
            mock_logger.error.assert_any_call("Packages feed health check failed: Feed service exception")
            mock_logger.error.assert_any_call("Registry service health check failed: Registry service exception")
            mock_logger.error.assert_any_call("Notification service health check failed: Notification service exception")
            mock_logger.error.assert_any_call("Storage service health check failed: Storage service exception")

    @pytest.mark.asyncio
    async def test_scan_result_duration_calculation(self, security_scanner, mock_packages_feed):
        """Test that scan result correctly calculates execution duration."""
        mock_packages_feed.fetch_malicious_packages.return_value = []
        
        with patch('src.core.usecases.security_scanner.datetime') as mock_datetime:
            start_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            end_time = datetime(2023, 1, 1, 12, 0, 30, 500000, tzinfo=timezone.utc)  # 30.5 seconds later
            
            mock_datetime.now.side_effect = [start_time, end_time, end_time]  # Called 3 times
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
            
            result = await security_scanner.execute_scan()
            
            assert result.execution_duration_seconds == 30.5

    @pytest.mark.asyncio
    async def test_scan_id_generation(self, security_scanner, mock_packages_feed):
        """Test that each scan generates a unique scan ID."""
        mock_packages_feed.fetch_malicious_packages.return_value = []
        
        with patch('src.core.usecases.security_scanner.uuid.uuid4') as mock_uuid:
            test_uuid = uuid.UUID('12345678-1234-5678-9abc-123456789abc')
            mock_uuid.return_value = test_uuid
            
            result = await security_scanner.execute_scan()
            
            assert result.scan_id == str(test_uuid)
            mock_uuid.assert_called()

    def test_initialization(self, mock_packages_feed, mock_packages_registry, 
                           mock_notification_service, mock_storage_service):
        """Test SecurityScanner initialization."""
        scanner = SecurityScanner(
            packages_feed=mock_packages_feed,
            registry_service=mock_packages_registry,
            notification_service=mock_notification_service,
            storage_service=mock_storage_service
        )
        
        assert scanner._packages_feed == mock_packages_feed
        assert scanner._registry_service == mock_packages_registry
        assert scanner._notification_service == mock_notification_service
        assert scanner._storage_service == mock_storage_service