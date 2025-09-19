"""Tests for notification service interface and implementations."""

import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime, timezone

from src.core.interfaces.notification_service import NotificationService
from src.core.entities import (
    NotificationEvent, NotificationLevel, NotificationChannel, 
    ScanResult, ScanStatus
)


class MockNotificationService(NotificationService):
    """Mock implementation of NotificationService for testing."""
    
    def __init__(self):
        self.sent_notifications = []
        self.healthy = True
        self.send_notification_call_count = 0
        self.health_check_call_count = 0
        self.should_raise_error = False
        self.error_message = "Mock error"
        self.send_success = True
        
    async def send_notification(self, event: NotificationEvent) -> bool:
        """Mock implementation of send_notification."""
        self.send_notification_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        if self.send_success:
            self.sent_notifications.append(event)
            return True
        else:
            return False
    
    async def health_check(self) -> bool:
        """Mock implementation of health_check."""
        self.health_check_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        return self.healthy


class TestNotificationServiceInterface:
    """Test cases for NotificationService interface."""
    
    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample scan result for testing."""
        return ScanResult(
            scan_id="test-scan-001",
            timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=100,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=30.5
        )
    
    @pytest.fixture
    def sample_notification_event(self, sample_scan_result):
        """Create a sample notification event for testing."""
        return NotificationEvent(
            event_id="notif-001",
            timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
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
    def mock_notification_service(self):
        """Create a mock notification service."""
        return MockNotificationService()
    
    def test_mock_notification_service_initialization(self):
        """Test mock notification service initialization."""
        service = MockNotificationService()
        
        assert service.sent_notifications == []
        assert service.healthy is True
        assert service.send_notification_call_count == 0
        assert service.health_check_call_count == 0
        assert service.should_raise_error is False
        assert service.send_success is True
    
    @pytest.mark.asyncio
    async def test_send_notification_success(self, mock_notification_service, sample_notification_event):
        """Test successful notification sending."""
        result = await mock_notification_service.send_notification(sample_notification_event)
        
        assert result is True
        assert mock_notification_service.send_notification_call_count == 1
        assert len(mock_notification_service.sent_notifications) == 1
        assert mock_notification_service.sent_notifications[0] == sample_notification_event
    
    @pytest.mark.asyncio
    async def test_send_notification_failure(self, mock_notification_service, sample_notification_event):
        """Test notification sending failure."""
        mock_notification_service.send_success = False
        
        result = await mock_notification_service.send_notification(sample_notification_event)
        
        assert result is False
        assert mock_notification_service.send_notification_call_count == 1
        assert len(mock_notification_service.sent_notifications) == 0
    
    @pytest.mark.asyncio
    async def test_send_notification_error(self, mock_notification_service, sample_notification_event):
        """Test notification sending when error occurs."""
        mock_notification_service.should_raise_error = True
        mock_notification_service.error_message = "Notification service down"
        
        with pytest.raises(Exception, match="Notification service down"):
            await mock_notification_service.send_notification(sample_notification_event)
        
        assert mock_notification_service.send_notification_call_count == 1
        assert len(mock_notification_service.sent_notifications) == 0
    
    @pytest.mark.asyncio
    async def test_send_multiple_notifications(self, mock_notification_service, sample_scan_result):
        """Test sending multiple notifications."""
        events = []
        for i in range(3):
            event = NotificationEvent(
                event_id=f"notif-{i:03d}",
                timestamp=datetime(2023, 1, 1, 12, i, 0, tzinfo=timezone.utc),
                level=NotificationLevel.INFO,
                title=f"Test Notification {i}",
                message=f"Test message {i}",
                scan_result=sample_scan_result,
                affected_packages=[],
                recommended_actions=[],
                channels=[NotificationChannel.SLACK],
                metadata={"test": True}
            )
            events.append(event)
            
            result = await mock_notification_service.send_notification(event)
            assert result is True
        
        assert mock_notification_service.send_notification_call_count == 3
        assert len(mock_notification_service.sent_notifications) == 3
        
        # Verify all events were stored in order
        for i, stored_event in enumerate(mock_notification_service.sent_notifications):
            assert stored_event.event_id == f"notif-{i:03d}"
            assert stored_event.title == f"Test Notification {i}"
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_notification_service):
        """Test health check when service is healthy."""
        result = await mock_notification_service.health_check()
        
        assert result is True
        assert mock_notification_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_notification_service):
        """Test health check when service is unhealthy."""
        mock_notification_service.healthy = False
        
        result = await mock_notification_service.health_check()
        
        assert result is False
        assert mock_notification_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_error(self, mock_notification_service):
        """Test health check when error occurs."""
        mock_notification_service.should_raise_error = True
        mock_notification_service.error_message = "Health check failed"
        
        with pytest.raises(Exception, match="Health check failed"):
            await mock_notification_service.health_check()
        
        assert mock_notification_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_notification_event_different_levels(self, mock_notification_service, sample_scan_result):
        """Test sending notifications with different severity levels."""
        levels = [NotificationLevel.INFO, NotificationLevel.WARNING, 
                 NotificationLevel.CRITICAL]
        
        for level in levels:
            event = NotificationEvent(
                event_id=f"notif-{level.value}",
                timestamp=datetime.now(timezone.utc),
                level=level,
                title=f"Test {level.value} Notification",
                message=f"Test {level.value} message",
                scan_result=sample_scan_result,
                affected_packages=[],
                recommended_actions=[],
                channels=[NotificationChannel.EMAIL],
                metadata={"level": level.value}
            )
            
            result = await mock_notification_service.send_notification(event)
            assert result is True
        
        assert len(mock_notification_service.sent_notifications) == 3
        
        # Verify different levels were processed
        sent_levels = [event.level for event in mock_notification_service.sent_notifications]
        assert set(sent_levels) == set(levels)
    
    @pytest.mark.asyncio
    async def test_notification_event_different_channels(self, mock_notification_service, sample_scan_result):
        """Test sending notifications to different channels."""
        channels_list = [
            [NotificationChannel.EMAIL],
            [NotificationChannel.SLACK],
            [NotificationChannel.EMAIL, NotificationChannel.SLACK],
            []  # No channels
        ]
        
        for i, channels in enumerate(channels_list):
            event = NotificationEvent(
                event_id=f"notif-{i}",
                timestamp=datetime.now(timezone.utc),
                level=NotificationLevel.INFO,
                title=f"Test Channel Notification {i}",
                message=f"Test message for channels: {channels}",
                scan_result=sample_scan_result,
                affected_packages=[],
                recommended_actions=[],
                channels=channels,
                metadata={"channels": [ch.value for ch in channels]}
            )
            
            result = await mock_notification_service.send_notification(event)
            assert result is True
        
        assert len(mock_notification_service.sent_notifications) == 4
    
    @pytest.mark.asyncio
    async def test_interface_contract_compliance(self, mock_notification_service, sample_notification_event):
        """Test that mock implementation complies with interface contract."""
        # Verify it's an instance of the interface
        assert isinstance(mock_notification_service, NotificationService)
        
        # Verify methods exist and are callable
        assert hasattr(mock_notification_service, 'send_notification')
        assert hasattr(mock_notification_service, 'health_check')
        assert callable(mock_notification_service.send_notification)
        assert callable(mock_notification_service.health_check)
        
        # Test methods return expected types
        send_result = await mock_notification_service.send_notification(sample_notification_event)
        assert isinstance(send_result, bool)
        
        health_result = await mock_notification_service.health_check()
        assert isinstance(health_result, bool)
    
    def test_interface_is_abstract(self):
        """Test that NotificationService interface cannot be instantiated directly."""
        with pytest.raises(TypeError):
            NotificationService()  # pylint: disable=abstract-class-instantiated
    
    @pytest.mark.asyncio
    async def test_concurrent_notifications(self, mock_notification_service, sample_scan_result):
        """Test concurrent notification sending."""
        import asyncio
        
        # Create multiple notification events
        events = []
        for i in range(5):
            event = NotificationEvent(
                event_id=f"concurrent-{i}",
                timestamp=datetime.now(timezone.utc),
                level=NotificationLevel.INFO,
                title=f"Concurrent Notification {i}",
                message=f"Concurrent message {i}",
                scan_result=sample_scan_result,
                affected_packages=[],
                recommended_actions=[],
                channels=[NotificationChannel.EMAIL],
                metadata={"concurrent": True, "index": i}
            )
            events.append(event)
        
        # Send all notifications concurrently
        tasks = [mock_notification_service.send_notification(event) for event in events]
        results = await asyncio.gather(*tasks)
        
        # Verify all succeeded
        assert all(result is True for result in results)
        assert mock_notification_service.send_notification_call_count == 5
        assert len(mock_notification_service.sent_notifications) == 5
        
        # Verify all events were stored (order may vary due to concurrency)
        sent_event_ids = {event.event_id for event in mock_notification_service.sent_notifications}
        expected_event_ids = {f"concurrent-{i}" for i in range(5)}
        assert sent_event_ids == expected_event_ids
    
    @pytest.mark.asyncio
    async def test_mixed_success_failure_scenarios(self, mock_notification_service, sample_scan_result):
        """Test mixed success and failure scenarios."""
        events = []
        for i in range(3):
            event = NotificationEvent(
                event_id=f"mixed-{i}",
                timestamp=datetime.now(timezone.utc),
                level=NotificationLevel.INFO,
                title=f"Mixed Test {i}",
                message=f"Mixed message {i}",
                scan_result=sample_scan_result,
                affected_packages=[],
                recommended_actions=[],
                channels=[NotificationChannel.EMAIL],
                metadata={"mixed": True}
            )
            events.append(event)
        
        # First notification succeeds
        result1 = await mock_notification_service.send_notification(events[0])
        assert result1 is True
        
        # Second notification fails
        mock_notification_service.send_success = False
        result2 = await mock_notification_service.send_notification(events[1])
        assert result2 is False
        
        # Third notification succeeds again
        mock_notification_service.send_success = True
        result3 = await mock_notification_service.send_notification(events[2])
        assert result3 is True
        
        # Verify state
        assert mock_notification_service.send_notification_call_count == 3
        assert len(mock_notification_service.sent_notifications) == 2  # Only successes are stored
        
        # Verify correct events were stored
        sent_event_ids = [event.event_id for event in mock_notification_service.sent_notifications]
        assert "mixed-0" in sent_event_ids
        assert "mixed-1" not in sent_event_ids  # Failed
        assert "mixed-2" in sent_event_ids
    
    @pytest.mark.asyncio
    async def test_large_notification_payload(self, mock_notification_service, sample_scan_result):
        """Test sending notification with large payload."""
        # Create a notification with large metadata
        large_metadata = {
            "large_data": "x" * 10000,  # 10KB of data
            "packages": [f"package-{i}" for i in range(1000)],  # Large list
            "details": {f"key-{i}": f"value-{i}" for i in range(100)}  # Large dict
        }
        
        event = NotificationEvent(
            event_id="large-payload",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.WARNING,
            title="Large Payload Notification",
            message="This notification has a large payload",
            scan_result=sample_scan_result,
            affected_packages=[],
            recommended_actions=["Action"] * 50,  # Large list
            channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
            metadata=large_metadata
        )
        
        result = await mock_notification_service.send_notification(event)
        
        assert result is True
        assert mock_notification_service.send_notification_call_count == 1
        assert len(mock_notification_service.sent_notifications) == 1
        
        # Verify the large payload was preserved
        stored_event = mock_notification_service.sent_notifications[0]
        assert stored_event.metadata["large_data"] == "x" * 10000
        assert len(stored_event.metadata["packages"]) == 1000
        assert len(stored_event.recommended_actions) == 50