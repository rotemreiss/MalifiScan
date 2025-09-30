"""Unit tests for MS Teams notification provider."""

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.core.entities import (
    MaliciousPackage,
    NotificationChannel,
    NotificationEvent,
    NotificationLevel,
    ScanResult,
    ScanStatus,
)
from src.providers.exceptions import NotificationError
from src.providers.notifications.msteams_notifier import MSTeamsNotifier


class TestMSTeamsNotifier:
    """Test suite for MS Teams notifier."""

    def test_init_with_webhook_url(self):
        """Test initialization with explicit webhook URL."""
        webhook_url = "https://prod-123.powerplatform.com/powerautomate/workflows/abc123/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        assert notifier.webhook_url == webhook_url
        assert notifier.timeout_seconds == 30
        assert notifier.max_retries == 3
        assert notifier.retry_delay == 1.0

    def test_init_with_env_variable(self):
        """Test initialization with environment variable."""
        webhook_url = "https://prod-456.powerplatform.com/powerautomate/workflows/env456/triggers/manual/paths/invoke"

        with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
            notifier = MSTeamsNotifier()
            assert notifier.webhook_url == webhook_url

    def test_init_without_webhook_url_raises_error(self):
        """Test that initialization without webhook URL raises error."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(NotificationError) as exc_info:
                MSTeamsNotifier()

            assert "MS Teams webhook URL not configured" in str(exc_info.value)

    def test_init_with_invalid_webhook_url_raises_error(self):
        """Test that initialization with invalid webhook URL raises error."""
        with pytest.raises(NotificationError) as exc_info:
            MSTeamsNotifier(webhook_url="invalid-url")

        assert "Invalid webhook URL format" in str(exc_info.value)

    def test_init_with_non_powerautomate_url_raises_error(self):
        """Test that initialization with non-Power Automate URL raises error."""
        webhook_url = "https://example.com/webhook"

        with pytest.raises(
            NotificationError,
            match="URL does not appear to be a Microsoft Power Automate workflow webhook",
        ):
            MSTeamsNotifier(webhook_url=webhook_url)

    def test_init_with_custom_config(self):
        """Test initialization with custom configuration."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(
            webhook_url=webhook_url, timeout_seconds=60, max_retries=5, retry_delay=2.0
        )

        assert notifier.timeout_seconds == 60
        assert notifier.max_retries == 5
        assert notifier.retry_delay == 2.0

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 200

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await notifier.health_check()

            assert result is True
            mock_post.assert_called_once()

            # Verify the test payload structure (standardized format for health check)
            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert isinstance(payload, dict)
            assert "title" in payload
            assert "🧪 MS Teams Health Check" in payload["title"]
            assert payload["level"] == "info"

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test health check failure."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad Request")

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await notifier.health_check()

            assert result is False

    @pytest.mark.asyncio
    async def test_health_check_exception(self):
        """Test health check with network exception."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.side_effect = aiohttp.ClientError("Network error")

            result = await notifier.health_check()

            assert result is False

    @pytest.mark.asyncio
    async def test_send_notification_success(self):
        """Test successful notification sending."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        # Create test notification event
        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="Test Notification",
            message="Test message",
            scan_result=scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        mock_response = MagicMock()
        mock_response.status = 200

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await notifier.send_notification(event)

            assert result is True
            mock_post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_notification_failure(self):
        """Test notification sending failure."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url, max_retries=1)

        # Create test notification event
        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="Test Notification",
            message="Test message",
            scan_result=scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Internal Server Error")

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await notifier.send_notification(event)

            assert result is False

    @pytest.mark.asyncio
    async def test_send_notification_permanent_error_no_retry(self):
        """Test that permanent errors (4xx) don't trigger retries."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url, max_retries=3)

        # Create test notification event
        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="Test Notification",
            message="Test message",
            scan_result=scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        mock_response = MagicMock()
        mock_response.status = 404  # Permanent error
        mock_response.text = AsyncMock(return_value="Not Found")

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response

            result = await notifier.send_notification(event)

            assert result is False
            # Should only be called once, no retries for permanent errors
            assert mock_post.call_count == 1

    @pytest.mark.asyncio
    async def test_send_notification_with_exception(self):
        """Test notification sending with exception returns False."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        # Create test notification event
        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="Test Notification",
            message="Test message",
            scan_result=scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.side_effect = aiohttp.ClientError("Network error")

            # Network errors should return False, not raise exception
            result = await notifier.send_notification(event)
            assert result is False

    def test_create_teams_payload_critical_notification(self):
        """Test Teams payload creation for critical notification."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        # Create test malicious package
        malicious_pkg = MaliciousPackage(
            name="test-package",
            version="1.0.0",
            ecosystem="npm",
            package_url="https://example.com/package",
            advisory_id="CVE-2023-12345",
            summary="Test malicious package",
            details="Test vulnerability details",
            aliases=["GHSA-test-123"],
            affected_versions=["1.0.0"],
            database_specific={"severity": "HIGH"},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        )

        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[malicious_pkg],
            packages_blocked=[],
            malicious_packages_list=[malicious_pkg],  # Found in registry
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.CRITICAL,
            title="🚨 Critical Security Alert",
            message="Malicious package detected",
            scan_result=scan_result,
            affected_packages=[malicious_pkg],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        payload = notifier._create_teams_payload(event)

        # Verify standardized payload structure
        assert payload["title"] == "🚨 Critical Security Alert"
        assert payload["message"] == "Malicious package detected"
        assert payload["level"] == "critical"

        # Verify scan result information
        assert payload["scan_result"]["scan_id"] == scan_result.scan_id
        assert payload["scan_result"]["malicious_packages_found"] == 1
        assert payload["scan_result"]["packages_scanned"] == 10

        # Verify affected packages information
        assert len(payload["affected_packages"]) == 1
        assert payload["affected_packages"][0]["name"] == "test-package"

    def test_create_teams_payload_info_notification(self):
        """Test Teams payload creation for info notification."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        scan_result = ScanResult(
            scan_id="test-scan-123",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=5.2,
        )

        event = NotificationEvent(
            event_id="test-event-123",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="✅ Scan Complete",
            message="No threats detected",
            scan_result=scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
        )

        payload = notifier._create_teams_payload(event)

        # Verify standardized payload structure
        assert payload["title"] == "✅ Scan Complete"
        assert payload["level"] == "info"

        # Verify no affected packages in payload
        assert payload["scan_result"]["malicious_packages_found"] == 0
        assert len(payload.get("affected_packages", [])) == 0

    def test_str_representation(self):
        """Test string representation of the notifier."""
        webhook_url = "https://prod-789.powerplatform.com/powerautomate/workflows/test789/triggers/manual/paths/invoke-very-long-url-that-should-be-truncated"
        notifier = MSTeamsNotifier(webhook_url=webhook_url)

        str_repr = str(notifier)
        assert "MSTeamsNotifier" in str_repr
        assert "..." in str_repr  # URL should be truncated
        assert len(str_repr) < 200  # Should be reasonably short
