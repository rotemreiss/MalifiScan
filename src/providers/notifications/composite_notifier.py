"""Composite notification provider that can send to multiple channels."""

import asyncio
import logging
from typing import List

from ...core.entities import NotificationEvent
from ...core.interfaces import NotificationService

logger = logging.getLogger(__name__)


class CompositeNotifier(NotificationService):
    """Composite notification provider that sends to multiple notification services."""

    def __init__(self, notifiers: List[NotificationService]):
        """
        Initialize composite notifier.

        Args:
            notifiers: List of notification services to use
        """
        self.notifiers = notifiers

        if not notifiers:
            raise ValueError("At least one notifier must be provided")

    async def send_notification(self, event: NotificationEvent) -> bool:
        """
        Send notification to all configured services.

        Args:
            event: The notification event to send

        Returns:
            True if at least one notification was sent successfully, False otherwise
        """
        logger.info(
            f"Sending notification to {len(self.notifiers)} services: {event.event_id}"
        )

        # Send to all notifiers concurrently
        tasks = []
        for notifier in self.notifiers:
            task = asyncio.create_task(self._send_to_notifier(notifier, event))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Count successful notifications
        successful_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Notifier {i} failed: {result}")
            elif result:
                successful_count += 1
            else:
                logger.warning(f"Notifier {i} returned False")

        success = successful_count > 0

        if success:
            logger.info(
                f"Successfully sent notification to {successful_count}/{len(self.notifiers)} services"
            )
        else:
            logger.error("Failed to send notification to any service")

        return success

    async def _send_to_notifier(
        self, notifier: NotificationService, event: NotificationEvent
    ) -> bool:
        """Send notification to a single notifier with error handling."""
        try:
            return await notifier.send_notification(event)
        except Exception as e:
            logger.error(f"Notifier {type(notifier).__name__} failed: {e}")
            return False

    async def health_check(self) -> bool:
        """
        Check health of all notification services.

        Returns:
            True if at least one service is healthy, False otherwise
        """
        logger.debug("Performing health check on all notification services")

        # Check all notifiers concurrently
        tasks = []
        for notifier in self.notifiers:
            task = asyncio.create_task(self._check_notifier_health(notifier))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Count healthy services
        healthy_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Health check failed for notifier {i}: {result}")
            elif result:
                healthy_count += 1

        is_healthy = healthy_count > 0
        logger.debug(
            f"Health check: {healthy_count}/{len(self.notifiers)} services healthy"
        )

        return is_healthy

    async def _check_notifier_health(self, notifier: NotificationService) -> bool:
        """Check health of a single notifier with error handling."""
        try:
            return await notifier.health_check()
        except Exception as e:
            logger.warning(f"Health check failed for {type(notifier).__name__}: {e}")
            return False
