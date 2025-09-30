"""Unit tests for NotificationTestingUseCase."""

import pytest

from src.core.entities import NotificationEvent, NotificationLevel
from src.core.interfaces import NotificationService
from src.core.usecases.notification_testing import NotificationTestingUseCase


class MockNotificationService(NotificationService):
    """Mock implementation of NotificationService for testing."""

    def __init__(self):
        """Initialize mock notification service."""
        self.sent_events = []
        self.send_notification_calls = 0
        self.health_check_calls = 0
        self.healthy = True
        self.send_notification_result = True
        self.health_check_result = True
        self.should_raise_error = False
        self.error_message = "Generic mock error"

    async def send_notification(self, event):
        """Mock send notification."""
        self.send_notification_calls += 1
        self.sent_events.append(event)

        if self.should_raise_error:
            raise Exception(self.error_message)

        return self.send_notification_result

    async def health_check(self):
        """Mock health check."""
        self.health_check_calls += 1

        if self.should_raise_error:
            raise Exception(self.error_message)

        return self.health_check_result


class TestNotificationTestingUseCase:
    """Test NotificationTestingUseCase."""

    @pytest.fixture
    def mock_notification_service(self):
        """Create mock notification service."""
        return MockNotificationService()

    @pytest.fixture
    def notification_testing_usecase(self, mock_notification_service):
        """Create notification testing use case."""
        return NotificationTestingUseCase(mock_notification_service)

    @pytest.mark.asyncio
    async def test_basic_notification_test_success(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test successful basic notification test."""
        result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )

        assert result["success"] is True
        assert result["notification_sent"] is True
        assert result["healthy"] is True
        assert result["test_type"] == "basic"
        assert "event_id" in result

        # Verify service calls
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 1
        assert len(mock_notification_service.sent_events) == 1

        # Verify event properties
        sent_event = mock_notification_service.sent_events[0]
        assert sent_event.level == NotificationLevel.INFO
        assert "🧪 Malifiscan Notification Test" in sent_event.title
        assert len(sent_event.affected_packages) == 0
        assert sent_event.registry_type == "test"

    @pytest.mark.asyncio
    async def test_malicious_package_notification_test_success(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test successful malicious package notification test."""
        result = await notification_testing_usecase.test_notification_service(
            include_malicious=True
        )

        assert result["success"] is True
        assert result["notification_sent"] is True
        assert result["healthy"] is True
        assert result["test_type"] == "malicious_package"
        assert result["affected_packages_count"] == 1
        assert "event_id" in result

        # Verify service calls
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 1
        assert len(mock_notification_service.sent_events) == 1

        # Verify event properties
        sent_event = mock_notification_service.sent_events[0]
        assert sent_event.level == NotificationLevel.CRITICAL
        assert "🚨 CRITICAL: Malicious Package Test Alert" in sent_event.title
        assert len(sent_event.affected_packages) == 1
        assert sent_event.affected_packages[0].name == "mal-test-pack"
        assert sent_event.affected_packages[0].version == "9.9.9"
        assert sent_event.registry_type == "test"
        assert sent_event.metadata["malicious_test"] is True

    @pytest.mark.asyncio
    async def test_health_check_failure(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test health check failure."""
        mock_notification_service.health_check_result = False

        result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )

        assert result["success"] is False
        assert result["healthy"] is False
        assert "error" in result

        # Verify only health check was called
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 0

    @pytest.mark.asyncio
    async def test_health_check_exception(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test health check exception."""
        mock_notification_service.should_raise_error = True
        mock_notification_service.error_message = "Health check failed"

        result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )

        assert result["success"] is False
        assert result["healthy"] is False
        assert "Health check error" in result["error"]

        # Verify only health check was called
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 0

    @pytest.mark.asyncio
    async def test_notification_send_failure(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test notification send failure."""
        mock_notification_service.send_notification_result = False

        result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )

        assert result["success"] is False
        assert result["notification_sent"] is False
        assert result["healthy"] is True  # Health check succeeded
        assert "error" in result

        # Verify both methods were called
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 1

    @pytest.mark.asyncio
    async def test_notification_send_exception(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test notification send exception."""
        # Reset error flag for health check to succeed
        mock_notification_service.should_raise_error = False

        # Create a service that succeeds health check but fails notification
        async def failing_send_notification(event):
            mock_notification_service.send_notification_calls += 1
            mock_notification_service.sent_events.append(event)
            raise Exception("Send notification failed")

        mock_notification_service.send_notification = failing_send_notification

        result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )

        assert result["success"] is False
        assert result["notification_sent"] is False
        assert result["healthy"] is True  # Health check succeeded
        assert "Test notification error" in result["error"]

        # Verify both methods were called
        assert mock_notification_service.health_check_calls == 1
        assert mock_notification_service.send_notification_calls == 1

    def test_create_basic_test_event(self, notification_testing_usecase):
        """Test creating basic test event."""
        event = notification_testing_usecase._create_basic_test_event()

        assert isinstance(event, NotificationEvent)
        assert event.level == NotificationLevel.INFO
        assert "🧪 Malifiscan Notification Test" in event.title
        assert len(event.affected_packages) == 0
        assert event.scan_result.packages_scanned == 5
        assert event.registry_type == "test"
        assert event.metadata["test"] is True

    def test_create_malicious_package_test_event(self, notification_testing_usecase):
        """Test creating malicious package test event."""
        event = notification_testing_usecase._create_malicious_package_test_event()

        assert isinstance(event, NotificationEvent)
        assert event.level == NotificationLevel.CRITICAL
        assert "🚨 CRITICAL: Malicious Package Test Alert" in event.title
        assert len(event.affected_packages) == 1

        # Verify malicious package details
        malicious_pkg = event.affected_packages[0]
        assert malicious_pkg.name == "mal-test-pack"
        assert malicious_pkg.version == "9.9.9"
        assert malicious_pkg.ecosystem == "npm"
        assert malicious_pkg.advisory_id == "CLI-TEST-2025-001"
        assert "CRITICAL" in malicious_pkg.database_specific["severity"]

        # Verify scan result
        assert event.scan_result.packages_scanned == 10
        assert len(event.scan_result.malicious_packages_found) == 1
        assert event.registry_type == "test"
        assert event.metadata["malicious_test"] is True

    @pytest.mark.asyncio
    async def test_both_test_types_use_different_event_structures(
        self, notification_testing_usecase, mock_notification_service
    ):
        """Test that basic and malicious tests create different event structures."""
        # Test basic notification
        basic_result = await notification_testing_usecase.test_notification_service(
            include_malicious=False
        )
        basic_event = mock_notification_service.sent_events[0]

        # Reset mock for malicious test
        mock_notification_service.sent_events.clear()
        mock_notification_service.send_notification_calls = 0
        mock_notification_service.health_check_calls = 0

        # Test malicious notification
        malicious_result = await notification_testing_usecase.test_notification_service(
            include_malicious=True
        )
        malicious_event = mock_notification_service.sent_events[0]

        # Compare results
        assert basic_result["test_type"] == "basic"
        assert malicious_result["test_type"] == "malicious_package"
        assert malicious_result["affected_packages_count"] == 1
        assert "affected_packages_count" not in basic_result

        # Compare events
        assert basic_event.level == NotificationLevel.INFO
        assert malicious_event.level == NotificationLevel.CRITICAL
        assert len(basic_event.affected_packages) == 0
        assert len(malicious_event.affected_packages) == 1
        assert basic_event.scan_result.packages_scanned == 5
        assert malicious_event.scan_result.packages_scanned == 10
