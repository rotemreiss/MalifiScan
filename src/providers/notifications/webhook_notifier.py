"""Generic webhook notification provider with standard payload format."""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import aiohttp

from ...core.entities import NotificationEvent, NotificationLevel
from ...core.interfaces import NotificationService
from ..exceptions import NotificationError

logger = logging.getLogger(__name__)


class WebhookNotifier(NotificationService):
    """
    Generic webhook notification provider with standard JSON payload format.

    Sends notifications to webhook endpoints using a consistent, standardized
    JSON payload structure suitable for most webhook consumers.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """
        Initialize webhook notifier.

        Args:
            webhook_url: Target webhook URL (can also be set via env WEBHOOK_URL)
            custom_headers: Additional HTTP headers to send
            timeout_seconds: Request timeout
            max_retries: Maximum retry attempts
            retry_delay: Delay between retries in seconds

        Raises:
            NotificationError: If webhook URL is not provided or invalid
        """
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")
        self.custom_headers = custom_headers or {}
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        if not self.webhook_url:
            raise NotificationError(
                "Webhook URL not configured. "
                "Set WEBHOOK_URL environment variable or provide webhook_url parameter in configuration."
            )

        # Validate webhook URL format
        parsed_url = urlparse(self.webhook_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise NotificationError(f"Invalid webhook URL format: {self.webhook_url}")

        if parsed_url.scheme not in ["http", "https"]:
            raise NotificationError(
                f"Webhook URL must use HTTP or HTTPS: {self.webhook_url}"
            )

    async def send_notification(self, event: NotificationEvent) -> bool:
        """
        Send notification via webhook.

        Args:
            event: Notification event to send

        Returns:
            True if sent successfully, False otherwise

        Raises:
            NotificationError: If sending fails unexpectedly
        """
        logger.debug(f"Sending webhook notification: {event.event_id}")

        try:
            # Create standard payload
            payload = self._create_webhook_payload(event)

            # Send with retries
            success = await self._send_with_retries(payload)

            if success:
                logger.info(f"Successfully sent webhook notification {event.event_id}")
            else:
                logger.error(
                    f"Failed to send webhook notification {event.event_id} after {self.max_retries} attempts"
                )

            return success

        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            raise NotificationError(f"Failed to send webhook notification: {e}")

    async def health_check(self) -> bool:
        """
        Perform health check by sending test payload.

        Returns:
            True if webhook is reachable and responds successfully
        """
        logger.debug("Performing webhook health check")

        try:
            test_payload = self._create_test_payload()
            success = await self._send_with_retries(test_payload)

            if success:
                logger.debug("Webhook health check passed")
            else:
                logger.warning("Webhook health check failed")

            return success

        except Exception as e:
            logger.error(f"Webhook health check error: {e}")
            return False

    def _create_webhook_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create webhook payload from notification event.

        Args:
            event: Notification event to convert

        Returns:
            Dictionary representing webhook payload in standard format
        """
        return self._create_standard_payload(event)

    def _create_standard_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create standard webhook payload format using the event's standardized method.

        Args:
            event: Notification event to convert

        Returns:
            Dictionary representing standard webhook payload
        """
        # Use the standardized payload method from NotificationEvent
        payload = event.to_standard_payload()

        # Add webhook-specific enhancements
        color_map = {
            NotificationLevel.INFO: "#2196f3",  # Blue
            NotificationLevel.WARNING: "#ff9800",  # Orange
            NotificationLevel.CRITICAL: "#d32f2f",  # Red
        }
        payload["color"] = color_map.get(event.level, "#2196f3")

        return payload

    def _create_test_payload(self) -> Dict[str, Any]:
        """
        Create test payload for health checks using the standard format.

        Returns:
            Dictionary representing test payload in standard format
        """
        import uuid

        from ...core.entities.notification_event import (
            NotificationChannel,
            NotificationEvent,
            NotificationLevel,
        )
        from ...core.entities.scan_result import ScanResult, ScanStatus

        # Create a test scan result
        test_scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=2.5,
        )

        # Create test notification event
        test_event = NotificationEvent(
            event_id=f"test-{uuid.uuid4()}",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="🧪 Malifiscan Notification Test",
            message="This is a test notification to verify that the notification system is working correctly. If you receive this message, your notification configuration is properly set up.",
            scan_result=test_scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={"test": True},
            registry_type="health_check",
            registry_url="health://webhook-connectivity-test",
        )

        return self._create_standard_payload(test_event)

    def _get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for webhook requests.

        Returns:
            Dictionary of HTTP headers
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Malifiscan-Security-Scanner/1.0",
        }

        # Add custom headers
        headers.update(self.custom_headers)

        return headers

    async def _send_with_retries(self, payload: Dict[str, Any]) -> bool:
        """
        Send webhook payload with retry logic.

        Args:
            payload: JSON payload to send

        Returns:
            True if sent successfully, False otherwise
        """
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.webhook_url,
                        json=payload,
                        headers=self._get_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    ) as response:

                        if response.status in [200, 201, 202, 204]:
                            logger.debug(
                                f"Webhook notification sent successfully: HTTP {response.status}"
                            )
                            return True

                        # Log response details for debugging
                        response_text = await response.text()
                        logger.warning(
                            f"Webhook returned HTTP {response.status}: {response_text}"
                        )

                        # Some status codes indicate permanent failure, don't retry
                        if response.status in [400, 401, 403, 404, 405]:
                            logger.error(
                                f"Permanent error from webhook: HTTP {response.status}"
                            )
                            return False

                        # For other errors, we'll retry
                        if attempt < self.max_retries:
                            logger.debug(
                                f"Retrying webhook notification (attempt {attempt + 1}/{self.max_retries})"
                            )
                            await asyncio.sleep(self.retry_delay)

            except Exception as e:
                last_exception = e
                logger.warning(
                    f"Webhook notification attempt {attempt + 1} failed: {e}"
                )

                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)

        # All attempts failed
        if last_exception:
            logger.error(
                f"All webhook notification attempts failed. Last error: {last_exception}"
            )

        return False

    def __str__(self) -> str:
        """String representation of the notifier."""
        masked_url = (
            self.webhook_url[:50] + "..."
            if len(self.webhook_url) > 50
            else self.webhook_url
        )
        return f"WebhookNotifier(url={masked_url})"
