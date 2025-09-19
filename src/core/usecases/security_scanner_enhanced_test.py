"""Enhanced tests for security scanner to improve coverage."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock, Mock
from datetime import datetime, timezone
import uuid

from src.core.usecases.security_scanner import SecurityScanner, SecurityScannerError
from src.core.entities import (
    ScanStatus, MaliciousPackage, ScanResult, NotificationEvent, 
    NotificationLevel, NotificationChannel
)


class TestSecurityScannerEnhanced:
    """Enhanced tests for SecurityScanner to improve coverage."""

    @pytest.fixture
    def sample_malicious_packages(self):
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
    def mock_services(self):
        """Create all mock services with default behavior."""
        mock_feed = AsyncMock()
        mock_feed.fetch_malicious_packages.return_value = []
        mock_feed.health_check.return_value = True

        mock_registry = AsyncMock()
        mock_registry.check_existing_packages.return_value = []
        mock_registry.block_packages.return_value = []
        mock_registry.health_check.return_value = True

        mock_notification = AsyncMock()
        mock_notification.send_notification.return_value = True
        mock_notification.health_check.return_value = True

        mock_storage = AsyncMock()
        mock_storage.store_scan_result.return_value = None
        mock_storage.store_malicious_packages.return_value = None
        mock_storage.health_check.return_value = True

        return {
            'feed': mock_feed,
            'registry': mock_registry,
            'notification': mock_notification,
            'storage': mock_storage
        }

    @pytest.fixture
    def security_scanner(self, mock_services):
        """Create security scanner with mocked services."""
        return SecurityScanner(
            packages_feed=mock_services['feed'],
            registry_service=mock_services['registry'],
            notification_service=mock_services['notification'],
            storage_service=mock_services['storage']
        )

    def test_initialization(self, mock_services):
        """Test SecurityScanner initialization."""
        scanner = SecurityScanner(
            packages_feed=mock_services['feed'],
            registry_service=mock_services['registry'],
            notification_service=mock_services['notification'],
            storage_service=mock_services['storage']
        )
        
        assert scanner._packages_feed == mock_services['feed']
        assert scanner._registry_service == mock_services['registry']
        assert scanner._notification_service == mock_services['notification']
        assert scanner._storage_service == mock_services['storage']

    @pytest.mark.asyncio
    async def test_execute_scan_empty_feed(self, security_scanner, mock_services):
        """Test scan execution when feed returns no packages."""
        # Feed returns empty list
        mock_services['feed'].fetch_malicious_packages.return_value = []
        
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
        mock_services['feed'].fetch_malicious_packages.assert_called_once()
        mock_services['registry'].check_existing_packages.assert_called_once_with([])
        mock_services['registry'].block_packages.assert_not_called()
        mock_services['storage'].store_scan_result.assert_called_once()
        mock_services['storage'].store_malicious_packages.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_execute_scan_mixed_scenarios(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan with mixed scenarios - some new, some existing packages."""
        # Setup: 3 packages from feed, 1 already exists, 2 are new and get blocked
        all_packages = sample_malicious_packages
        existing_packages = [sample_malicious_packages[0]]  # First package already exists
        new_packages = sample_malicious_packages[1:]  # Last two are new
        blocked_identifiers = [pkg.package_identifier for pkg in new_packages]
        
        mock_services['feed'].fetch_malicious_packages.return_value = all_packages
        mock_services['registry'].check_existing_packages.return_value = existing_packages
        mock_services['registry'].block_packages.return_value = blocked_identifiers
        
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
        mock_services['registry'].block_packages.assert_called_once_with(new_packages)

    @pytest.mark.asyncio
    async def test_execute_scan_all_packages_already_exist(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan when all packages already exist in registry."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = sample_malicious_packages
        mock_services['registry'].block_packages.return_value = []
        
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
        mock_services['registry'].block_packages.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_scan_partial_blocking_failure(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan when some packages fail to be blocked."""
        new_packages = sample_malicious_packages
        # Only one package gets blocked successfully
        partially_blocked = [sample_malicious_packages[0].package_identifier]
        
        mock_services['feed'].fetch_malicious_packages.return_value = new_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = partially_blocked
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 3
        assert len(result.malicious_packages_found) == 3
        assert len(result.packages_blocked) == 1  # Only one was blocked
        assert len(result.malicious_packages_list) == 0
        assert result.is_successful
        assert result.has_new_threats

    @pytest.mark.asyncio
    async def test_execute_scan_storage_service_both_operations_fail(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan when both storage operations fail."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
        # Both storage operations fail
        mock_services['storage'].store_scan_result.side_effect = Exception("Scan result storage failed")
        mock_services['storage'].store_malicious_packages.side_effect = Exception("Package storage failed")
        
        result = await security_scanner.execute_scan()
        
        # Scan should still succeed despite storage failures
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful
        assert len(result.errors) >= 1  # Should contain storage error
        assert any("Storage error" in error for error in result.errors)

    @pytest.mark.asyncio
    async def test_execute_scan_notification_failure(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan when notification sending fails."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        mock_services['notification'].send_notification.side_effect = Exception("Notification service down")
        
        # Should not raise exception - notification failure shouldn't fail scan
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful

    @pytest.mark.asyncio
    async def test_execute_scan_notification_returns_false(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan when notification service returns False."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        mock_services['notification'].send_notification.return_value = False  # Returns False instead of True
        
        result = await security_scanner.execute_scan()
        
        assert result.status == ScanStatus.SUCCESS
        assert result.is_successful

    @pytest.mark.asyncio
    async def test_execute_scan_with_logging(self, security_scanner, mock_services, sample_malicious_packages):
        """Test scan execution with logging verification."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
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
    async def test_execute_scan_failed_scan_storage_attempt(self, security_scanner, mock_services):
        """Test that failed scan results are attempted to be stored."""
        # Make feed fail
        mock_services['feed'].fetch_malicious_packages.side_effect = Exception("Feed connection failed")
        
        with pytest.raises(SecurityScannerError, match="Scan failed"):
            await security_scanner.execute_scan()
        
        # Verify that store_scan_result was called even for failed scan
        mock_services['storage'].store_scan_result.assert_called_once()
        
        # Check that the stored result has FAILED status
        stored_result = mock_services['storage'].store_scan_result.call_args[0][0]
        assert stored_result.status == ScanStatus.FAILED
        assert len(stored_result.errors) > 0

    @pytest.mark.asyncio
    async def test_execute_scan_failed_scan_storage_also_fails(self, security_scanner, mock_services):
        """Test when scan fails and storing the failed result also fails."""
        # Make feed fail
        mock_services['feed'].fetch_malicious_packages.side_effect = Exception("Feed connection failed")
        # Make storage fail too
        mock_services['storage'].store_scan_result.side_effect = Exception("Storage completely down")
        
        with patch('src.core.usecases.security_scanner.logger') as mock_logger:
            with pytest.raises(SecurityScannerError, match="Scan failed"):
                await security_scanner.execute_scan()
            
            # Should log the storage error
            mock_logger.error.assert_any_call("Failed to store failed scan result: Storage completely down")

    @pytest.mark.asyncio
    async def test_execute_scan_failed_scan_notification_also_fails(self, security_scanner, mock_services):
        """Test when scan fails and notification also fails."""
        # Make feed fail
        mock_services['feed'].fetch_malicious_packages.side_effect = Exception("Feed connection failed")
        # Make notification fail too
        mock_services['notification'].send_notification.side_effect = Exception("Notification service down")
        
        with pytest.raises(SecurityScannerError, match="Scan failed"):
            await security_scanner.execute_scan()
        
        # Both storage and notification should be attempted
        mock_services['storage'].store_scan_result.assert_called_once()
        mock_services['notification'].send_notification.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_notification_success(self, security_scanner, mock_services):
        """Test successful notification sending."""
        # Create a sample scan result
        scan_result = ScanResult(
            scan_id="test-scan",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=30.0
        )
        
        mock_services['notification'].send_notification.return_value = True
        
        with patch('src.core.usecases.security_scanner.logger') as mock_logger:
            # Call the private method directly to test it
            await security_scanner._send_notification(scan_result)
            
            mock_logger.info.assert_called_with("Notification sent successfully")

    @pytest.mark.asyncio
    async def test_send_notification_with_uuid_generation(self, security_scanner, mock_services):
        """Test notification sending with UUID generation."""
        scan_result = ScanResult(
            scan_id="test-scan",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=30.0
        )
        
        with patch('src.core.usecases.security_scanner.uuid.uuid4') as mock_uuid:
            mock_uuid.return_value = uuid.UUID('12345678-1234-5678-9abc-123456789abc')
            
            await security_scanner._send_notification(scan_result)
            
            # Verify UUID was generated for notification event
            mock_uuid.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_all_services_exception(self, security_scanner, mock_services):
        """Test health check when all services raise exceptions."""
        # Make all services raise exceptions
        mock_services['feed'].health_check.side_effect = Exception("Feed service exception")
        mock_services['registry'].health_check.side_effect = Exception("Registry service exception")
        mock_services['notification'].health_check.side_effect = Exception("Notification service exception")
        mock_services['storage'].health_check.side_effect = Exception("Storage service exception")
        
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
    async def test_health_check_partial_failures(self, security_scanner, mock_services):
        """Test health check with some services healthy and some failing."""
        # Mix of healthy and failing services
        mock_services['feed'].health_check.return_value = True
        mock_services['registry'].health_check.side_effect = Exception("Registry down")
        mock_services['notification'].health_check.return_value = False  # Returns False
        mock_services['storage'].health_check.return_value = True
        
        health_status = await security_scanner.health_check()
        
        assert health_status["packages_feed"] is True
        assert health_status["registry_service"] is False
        assert health_status["notification_service"] is False
        assert health_status["storage_service"] is True
        assert health_status["overall"] is False  # Not all services are healthy

    @pytest.mark.asyncio
    async def test_notification_event_creation_details(self, security_scanner, mock_services, sample_malicious_packages):
        """Test that notification event is created with correct details."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
        with patch('src.core.entities.NotificationEvent.create_threat_notification') as mock_create_notification:
            mock_notification_event = Mock()
            mock_create_notification.return_value = mock_notification_event
            
            await security_scanner.execute_scan()
            
            # Verify notification event creation
            mock_create_notification.assert_called_once()
            call_args = mock_create_notification.call_args
            
            # Check that the call includes expected parameters
            assert 'event_id' in call_args.kwargs
            assert 'scan_result' in call_args.kwargs
            assert 'channels' in call_args.kwargs
            assert 'metadata' in call_args.kwargs
            
            # Check channels
            channels = call_args.kwargs['channels']
            assert NotificationChannel.SLACK in channels
            assert NotificationChannel.EMAIL in channels
            
            # Check metadata
            metadata = call_args.kwargs['metadata']
            assert metadata['scanner_version'] == "1.0.0"
            assert metadata['environment'] == "production"

    @pytest.mark.asyncio
    async def test_scan_result_duration_calculation(self, security_scanner, mock_services):
        """Test that scan result correctly calculates execution duration."""
        mock_services['feed'].fetch_malicious_packages.return_value = []
        
        with patch('src.core.usecases.security_scanner.datetime') as mock_datetime:
            start_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            end_time = datetime(2023, 1, 1, 12, 0, 30, 500000, tzinfo=timezone.utc)  # 30.5 seconds later
            
            mock_datetime.now.side_effect = [start_time, end_time, end_time]  # Called 3 times
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
            
            result = await security_scanner.execute_scan()
            
            assert result.execution_duration_seconds == 30.5

    @pytest.mark.asyncio
    async def test_scan_id_generation(self, security_scanner, mock_services):
        """Test that each scan generates a unique scan ID."""
        mock_services['feed'].fetch_malicious_packages.return_value = []
        
        with patch('src.core.usecases.security_scanner.uuid.uuid4') as mock_uuid:
            test_uuid = uuid.UUID('12345678-1234-5678-9abc-123456789abc')
            mock_uuid.return_value = test_uuid
            
            result = await security_scanner.execute_scan()
            
            assert result.scan_id == str(test_uuid)
            mock_uuid.assert_called()

    @pytest.mark.asyncio 
    async def test_store_malicious_packages_called(self, security_scanner, mock_services, sample_malicious_packages):
        """Test that store_malicious_packages is called with correct data."""
        mock_services['feed'].fetch_malicious_packages.return_value = sample_malicious_packages
        mock_services['registry'].check_existing_packages.return_value = []
        mock_services['registry'].block_packages.return_value = [pkg.package_identifier for pkg in sample_malicious_packages]
        
        await security_scanner.execute_scan()
        
        # Verify store_malicious_packages was called with the fetched packages
        mock_services['storage'].store_malicious_packages.assert_called_once_with(sample_malicious_packages)