"""Unit tests for generic webhook notification provider."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.providers.exceptions import NotificationError
from src.providers.notifications.webhook_notifier import WebhookNotifier


class TestWebhookNotifier:
    """Test suite for generic webhook notifier."""

    def test_init_with_webhook_url(self):
        """Test initialization with explicit webhook URL."""
        webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        assert notifier.webhook_url == webhook_url
        assert notifier.timeout_seconds == 30
        assert notifier.max_retries == 3
        assert notifier.retry_delay == 1.0
        assert notifier.custom_headers == {}

    def test_init_without_webhook_url_raises_error(self, monkeypatch):
        """Test that initialization without webhook URL raises error."""
        # Clear any environment variable that might be set
        monkeypatch.delenv("WEBHOOK_URL", raising=False)

        with pytest.raises(NotificationError, match="Webhook URL not configured"):
            WebhookNotifier()

    def test_init_with_invalid_webhook_url_raises_error(self):
        """Test that initialization with invalid webhook URL raises error."""
        with pytest.raises(NotificationError, match="Invalid webhook URL format"):
            WebhookNotifier(webhook_url="not-a-url")

    def test_init_with_invalid_scheme_raises_error(self):
        """Test that initialization with invalid URL scheme raises error."""
        with pytest.raises(
            NotificationError, match="Webhook URL must use HTTP or HTTPS"
        ):
            WebhookNotifier(webhook_url="ftp://example.com/webhook")

    @patch.dict("os.environ", {"WEBHOOK_URL": "https://example.com/webhook-from-env"})
    def test_init_with_environment_variable(self):
        """Test initialization using WEBHOOK_URL environment variable."""
        notifier = WebhookNotifier()

        assert notifier.webhook_url == "https://example.com/webhook-from-env"
        assert notifier.timeout_seconds == 30
        assert notifier.max_retries == 3

    @patch.dict("os.environ", {"WEBHOOK_URL": "invalid-url"})
    def test_init_with_invalid_environment_variable_raises_error(self):
        """Test that invalid environment variable URL raises error."""
        with pytest.raises(NotificationError, match="Invalid webhook URL format"):
            WebhookNotifier()

    @patch.dict("os.environ", {"WEBHOOK_URL": "https://valid-env-url.com/webhook"})
    def test_explicit_url_overrides_environment_variable(self):
        """Test that explicit webhook_url parameter overrides environment variable."""
        explicit_url = "https://explicit-url.com/webhook"
        notifier = WebhookNotifier(webhook_url=explicit_url)

        assert notifier.webhook_url == explicit_url
        # Verify env var is set but was overridden
        import os

        assert os.environ.get("WEBHOOK_URL") == "https://valid-env-url.com/webhook"

    def test_init_with_custom_config(self):
        """Test initialization with custom configuration."""
        webhook_url = (
            "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz"
        )
        custom_headers = {"Authorization": "Bearer token123"}

        notifier = WebhookNotifier(
            webhook_url=webhook_url,
            custom_headers=custom_headers,
            timeout_seconds=60,
            max_retries=5,
            retry_delay=2.0,
        )

        assert notifier.webhook_url == webhook_url
        assert notifier.custom_headers == custom_headers
        assert notifier.timeout_seconds == 60
        assert notifier.max_retries == 5
        assert notifier.retry_delay == 2.0

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 200

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            mock_post.return_value.__aexit__.return_value = False

            result = await notifier.health_check()

            assert result is True
            mock_post.assert_called_once()

            # Verify the headers include Content-Type and User-Agent
            call_args = mock_post.call_args
            headers = call_args[1]["headers"]
            assert headers["Content-Type"] == "application/json"
            assert "Malifiscan" in headers["User-Agent"]

    @pytest.mark.asyncio
    async def test_health_check_various_success_codes(self):
        """Test health check with various success status codes."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        success_codes = [200, 201, 202, 204]

        for status_code in success_codes:
            mock_response = MagicMock()
            mock_response.status = status_code

            with patch("aiohttp.ClientSession.post") as mock_post:
                mock_post.return_value.__aenter__.return_value = mock_response
                mock_post.return_value.__aexit__.return_value = False

                result = await notifier.health_check()
                assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test health check failure."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad Request")

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            mock_post.return_value.__aexit__.return_value = False

            result = await notifier.health_check()

            assert result is False

    @pytest.mark.asyncio
    async def test_health_check_exception(self):
        """Test health check with network exception."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        with patch(
            "aiohttp.ClientSession.post",
            side_effect=aiohttp.ClientError("Network error"),
        ):
            result = await notifier.health_check()
            assert result is False

    @pytest.mark.asyncio
    async def test_send_notification_success(self, info_notification_event):
        """Test successful notification sending."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 200

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            mock_post.return_value.__aexit__.return_value = False

            result = await notifier.send_notification(info_notification_event)

            assert result is True
            mock_post.assert_called()

            # Verify payload structure (standard format)
            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert payload["title"] == "✅ Scan Complete"
            assert payload["message"] == "Security scan completed successfully"
            assert payload["level"] == "info"
            assert payload["color"] == "#2196f3"  # Blue for info
            assert payload["scan_result"]["scan_id"] == "test-scan-clean-123"

    @pytest.mark.asyncio
    async def test_send_notification_with_affected_packages(
        self, critical_notification_event
    ):
        """Test notification sending with affected packages."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        mock_response = MagicMock()
        mock_response.status = 200

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            mock_post.return_value.__aexit__.return_value = False

            result = await notifier.send_notification(critical_notification_event)

            assert result is True

            # Verify payload includes affected packages
            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert payload["level"] == "critical"
            assert payload["color"] == "#d32f2f"  # Red for critical
            assert len(payload["affected_packages"]) == 1
            assert (
                payload["affected_packages"][0]["name"] == "test-critical-npm"
            )  # sample_npm_malicious_package

            # Verify registry information is included
            assert "registry" in payload
            assert payload["registry"]["type"] == "jfrog"
            assert payload["registry"]["url"] == "https://test.jfrog.io"

    @pytest.mark.asyncio
    async def test_send_notification_failure_with_retries(
        self, basic_notification_event
    ):
        """Test notification sending failure with retries."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url, max_retries=2)

        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Internal Server Error")

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            mock_post.return_value.__aexit__.return_value = False

            result = await notifier.send_notification(basic_notification_event)

            assert result is False
            # Should be called 3 times (initial + 2 retries)
            assert mock_post.call_count == 3

    @pytest.mark.asyncio
    async def test_send_notification_permanent_error_no_retry(
        self, basic_notification_event
    ):
        """Test that permanent errors don't trigger retries."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL"
        notifier = WebhookNotifier(webhook_url=webhook_url, max_retries=3)

        # Test each permanent error code
        permanent_errors = [400, 401, 403, 404, 405]

        for error_code in permanent_errors:
            mock_response = MagicMock()
            mock_response.status = error_code
            mock_response.text = AsyncMock(return_value="Permanent Error")

            with patch("aiohttp.ClientSession.post") as mock_post:
                mock_post.return_value.__aenter__.return_value = mock_response
                mock_post.return_value.__aexit__.return_value = False

                result = await notifier.send_notification(basic_notification_event)

                assert result is False
                # Should only be called once (no retries for permanent errors)
                assert mock_post.call_count == 1

    def test_create_standard_payload(
        self, critical_notification_event, sample_npm_malicious_package
    ):
        """Test standard payload format creation."""
        webhook_url = "https://example.com/webhook"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        payload = notifier._create_webhook_payload(critical_notification_event)

        # Verify standard format structure
        assert payload["title"] == "🚨 Critical Security Alert"
        assert payload["message"] == "Malicious package detected"
        assert payload["level"] == "critical"
        assert payload["color"] == "#d32f2f"  # Red for critical
        assert payload["scan_result"]["scan_id"] == "test-scan-critical"
        assert len(payload["affected_packages"]) == 1

        # Verify registry information is included
        assert "registry" in payload
        assert payload["registry"]["type"] == "jfrog"
        assert payload["registry"]["url"] == "https://test.jfrog.io"

    def test_custom_headers_included(self):
        """Test that custom headers are included in requests."""
        webhook_url = "https://example.com/webhook"
        custom_headers = {"Authorization": "Bearer token123", "X-Custom": "value"}
        notifier = WebhookNotifier(
            webhook_url=webhook_url, custom_headers=custom_headers
        )

        headers = notifier._get_headers()

        assert headers["Content-Type"] == "application/json"
        assert "Malifiscan" in headers["User-Agent"]
        assert headers["Authorization"] == "Bearer token123"
        assert headers["X-Custom"] == "value"

    def test_str_representation(self):
        """Test string representation of the notifier."""
        webhook_url = "https://hooks.slack.com/services/TEST/WEBHOOK/URL-very-long-url-that-should-be-truncated"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        str_repr = str(notifier)
        assert "WebhookNotifier" in str_repr
        assert "..." in str_repr  # URL should be truncated
        assert len(str_repr) < 200  # Should be reasonably short

    def test_test_payload_format(self):
        """Test health check payload format."""
        webhook_url = "https://example.com/webhook"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        test_payload = notifier._create_test_payload()

        assert "title" in test_payload
        assert "message" in test_payload
        assert "level" in test_payload
        assert "timestamp" in test_payload
        assert "Notification Test" in test_payload["title"]
        assert test_payload["level"] == "info"
        assert test_payload["color"] == "#2196f3"  # Blue for info

    def test_payload_with_warnings(self, warning_notification_event):
        """Test payload creation for warning-level events."""
        webhook_url = "https://example.com/webhook"
        notifier = WebhookNotifier(webhook_url=webhook_url)

        payload = notifier._create_webhook_payload(warning_notification_event)

        # Verify warning colors and structure
        assert payload["level"] == "warning"
        assert payload["color"] == "#ff9800"  # Orange for warning
        assert payload["title"] == "⚠️ Warning Alert"
