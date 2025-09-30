"""Null notification service for disabled notifications."""

import logging

from ...core.entities import NotificationEvent
from ...core.interfaces import NotificationService

logger = logging.getLogger(__name__)


class NullNotifier(NotificationService):
    """Null notification service that does nothing."""

    def __init__(self):
        """Initialize null notifier."""
        self.name = "NullNotifier"

    async def send_notification(self, event: NotificationEvent) -> bool:
        """
        Send notification (no-op).

        Args:
            event: Notification event to send

        Returns:
            True (always succeeds)
        """
        logger.debug(
            f"NullNotifier: Would send notification '{event.title}' (notifications disabled)"
        )
        return True

    async def health_check(self) -> bool:
        """
        Check service health.

        Returns:
            True (always healthy)
        """
        return True

    def __str__(self) -> str:
        return "NullNotifier(disabled)"
