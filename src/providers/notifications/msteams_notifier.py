"""Microsoft Teams notification provider using webhooks."""

import asyncio
import json
import logging
import os
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import aiohttp

from ...core.interfaces import NotificationService
from ...core.entities import NotificationEvent, NotificationLevel
from ..exceptions import NotificationError


logger = logging.getLogger(__name__)


class MSTeamsNotifier(NotificationService):
    """Microsoft Teams notification provider using webhooks."""
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        """
        Initialize MS Teams notifier.
        
        Args:
            webhook_url: MS Teams webhook URL (can also be set via env MSTEAMS_WEBHOOK_URL)
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            
        Raises:
            NotificationError: If webhook URL is not provided or invalid
        """
        self.webhook_url = webhook_url or os.getenv('MSTEAMS_WEBHOOK_URL')
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        if not self.webhook_url:
            raise NotificationError(
                "MS Teams webhook URL not configured. "
                "Set MSTEAMS_WEBHOOK_URL environment variable or provide webhook_url parameter."
            )
        
        # Validate webhook URL format
        parsed_url = urlparse(self.webhook_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise NotificationError(f"Invalid webhook URL format: {self.webhook_url}")
        
        # Validate it's a Power Automate workflow URL
        if not self._is_powerautomate_webhook(parsed_url):
            raise NotificationError(
                f"URL does not appear to be a Microsoft Power Automate workflow webhook. "
                f"Expected format: https://[environment].powerplatform.com/powerautomate/..."
            )
    
    def _is_powerautomate_webhook(self, parsed_url) -> bool:
        """
        Validate that the URL is a Power Automate workflow webhook.
        
        Args:
            parsed_url: Parsed URL object
            
        Returns:
            True if the URL is a valid Power Automate webhook, False otherwise
        """
        netloc = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # Check for Power Automate domain patterns
        if "powerplatform.com" not in netloc:
            return False
        
        # Check for Power Automate workflow path pattern
        if "powerautomate" not in path or "workflows" not in path:
            return False
        
        return True
    
    async def send_notification(self, event: NotificationEvent) -> bool:
        """
        Send notification to MS Teams channel via webhook.
        
        Args:
            event: Notification event to send
            
        Returns:
            True if notification was sent successfully, False otherwise
            
        Raises:
            NotificationError: If notification delivery fails
        """
        logger.info(f"Sending notification to MS Teams: {event.event_id}")
        
        try:
            # Convert notification event to Teams message card format
            teams_payload = self._create_teams_payload(event)
            
            # Send with retries
            success = await self._send_with_retries(teams_payload)
            
            if success:
                logger.info(f"Successfully sent notification {event.event_id} to MS Teams")
            else:
                logger.error(f"Failed to send notification {event.event_id} to MS Teams after {self.max_retries} attempts")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending notification to MS Teams: {e}")
            raise NotificationError(f"Failed to send MS Teams notification: {e}") from e
    
    async def health_check(self) -> bool:
        """
        Check if MS Teams webhook is accessible.
        
        Returns:
            True if webhook is accessible, False otherwise
        """
        logger.debug("Performing MS Teams webhook health check")
        
        try:
            # Try the most basic payload - just a string value
            # Many Power Automate workflows expect this simple format
            test_payload = "🔍 Malifiscan Health Check - This is a test message to verify MS Teams Power Automate webhook connectivity."
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as session:
                async with session.post(
                    self.webhook_url,
                    json=test_payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    
                    success = response.status == 200
                    
                    if success:
                        logger.debug("MS Teams webhook health check passed")
                    else:
                        logger.warning(f"MS Teams webhook health check failed: HTTP {response.status}")
                        response_text = await response.text()
                        logger.debug(f"Response: {response_text}")
                    
                    return success
                    
        except Exception as e:
            logger.warning(f"MS Teams webhook health check failed: {e}")
            return False
    
    def _create_teams_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create Power Automate workflow payload from notification event.
        
        Args:
            event: Notification event to convert
            
        Returns:
            Dictionary representing Power Automate payload
        """
        # Determine color/urgency based on notification level
        urgency_map = {
            NotificationLevel.INFO: "Normal",
            NotificationLevel.WARNING: "Important", 
            NotificationLevel.CRITICAL: "Urgent"
        }
        
        urgency = urgency_map.get(event.level, "Normal")
        
        # Build details text
        details_lines = [
            f"**Scan ID:** {event.scan_result.scan_id}",
            f"**Timestamp:** {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Packages Scanned:** {event.scan_result.packages_scanned}",
            f"**Status:** {event.scan_result.status.value.upper()}"
        ]
        
        # Add critical package details if present
        if event.affected_packages:
            details_lines.append(f"**Critical Packages Found:** {len(event.affected_packages)}")
            
            # Show up to 5 package names
            package_names = [pkg.name for pkg in event.affected_packages[:5]]
            if len(event.affected_packages) > 5:
                package_names.append(f"... and {len(event.affected_packages) - 5} more")
            
            details_lines.append(f"**Affected Packages:** {', '.join(package_names)}")
        
        # Add execution time
        if hasattr(event.scan_result, 'execution_duration_seconds'):
            details_lines.append(f"**Execution Time:** {event.scan_result.execution_duration_seconds:.1f}s")
        
        # Add recommended actions
        if event.recommended_actions:
            details_lines.append("\n**Recommended Actions:**")
            for action in event.recommended_actions:
                details_lines.append(f"• {action}")
        
        details_text = "\n".join(details_lines)
        
        # Create Power Automate payload
        payload = {
            "title": event.title,
            "text": event.message,
            "details": details_text,
            "urgency": urgency,
            "summary": f"Security scan completed with {event.scan_result.status.value} status",
            "scan_id": event.scan_result.scan_id,
            "packages_scanned": event.scan_result.packages_scanned,
            "critical_packages_found": len(event.affected_packages) if event.affected_packages else 0,
            "timestamp": event.timestamp.isoformat()
        }
        
        return payload
    
    async def _send_with_retries(self, payload: Dict[str, Any]) -> bool:
        """
        Send payload to Teams webhook with retry logic.
        
        Args:
            payload: Teams MessageCard payload
            
        Returns:
            True if sent successfully, False otherwise
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as session:
                    async with session.post(
                        self.webhook_url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    ) as response:
                        
                        if response.status == 200:
                            return True
                        
                        # Log error details for debugging
                        response_text = await response.text()
                        logger.warning(f"Teams webhook returned HTTP {response.status}: {response_text}")
                        
                        # Some status codes indicate permanent failure, don't retry
                        if response.status in [400, 401, 403, 404]:
                            logger.error(f"Permanent error from Teams webhook: HTTP {response.status}")
                            return False
                        
                        # For other errors, we'll retry
                        if attempt < self.max_retries:
                            logger.debug(f"Retrying Teams notification (attempt {attempt + 1}/{self.max_retries})")
                            await asyncio.sleep(self.retry_delay)
                        
            except Exception as e:
                last_exception = e
                logger.warning(f"Teams notification attempt {attempt + 1} failed: {e}")
                
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        # All attempts failed
        if last_exception:
            logger.error(f"All Teams notification attempts failed. Last error: {last_exception}")
        
        return False
    
    def __str__(self) -> str:
        """String representation of the notifier."""
        masked_url = self.webhook_url[:50] + "..." if len(self.webhook_url) > 50 else self.webhook_url
        return f"MSTeamsNotifier(webhook={masked_url})"