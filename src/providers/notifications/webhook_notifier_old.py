"""Generic webhook notification provider."""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from datetime import datetime

import aiohttp

from src.core.interfaces import NotificationService
from src.core.entities import NotificationEvent, NotificationLevel
from src.providers.exceptions import NotificationError

logger = logging.getLogger(__name__)


class WebhookNotifier(NotificationService):
    """
    Generic webhook notification provider.
    
    Sends notifications to any HTTP endpoint that accepts webhooks.
    Supports customizable payload formats for integration with various services.
    """
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        """
        Initialize webhook notifier.
        
        Args:
            webhook_url: Target webhook URL
            custom_headers: Additional HTTP headers to send
            timeout_seconds: Request timeout
            max_retries: Maximum retry attempts
            retry_delay: Delay between retries in seconds
            
        Raises:
            NotificationError: If webhook URL is not provided or invalid
        """
        self.webhook_url = webhook_url
        self.custom_headers = custom_headers or {}
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        if not self.webhook_url:
            raise NotificationError(
                "Webhook URL not configured. "
                "Provide webhook_url parameter in configuration."
            )
        
        # Validate webhook URL format
        parsed_url = urlparse(self.webhook_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise NotificationError(f"Invalid webhook URL format: {self.webhook_url}")
        
        if parsed_url.scheme not in ['http', 'https']:
            raise NotificationError(f"Webhook URL must use HTTP or HTTPS: {self.webhook_url}")
    
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
        logger.info(f"Sending webhook notification: {event.event_id}")
        
        try:
            # Create payload based on selected format
            payload = self._create_webhook_payload(event)
            
            # Send with retries
            success = await self._send_with_retries(payload)
            
            if success:
                logger.info(f"Successfully sent webhook notification {event.event_id}")
            else:
                logger.error(f"Failed to send webhook notification {event.event_id} after {self.max_retries} attempts")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            raise NotificationError(f"Failed to send webhook notification: {e}") from e
    
    async def health_check(self) -> bool:
        """
        Check if webhook endpoint is accessible.
        
        Returns:
            True if webhook is accessible, False otherwise
        """
        logger.debug("Performing webhook health check")
        
        try:
            # Create a minimal test payload
            test_payload = self._create_test_payload()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)) as session:
                async with session.post(
                    self.webhook_url,
                    json=test_payload,
                    headers=self._get_headers()
                ) as response:
                    
                    success = response.status in [200, 201, 202, 204]
                    
                    if success:
                        logger.debug("Webhook health check passed")
                    else:
                        logger.warning(f"Webhook health check failed: HTTP {response.status}")
                        response_text = await response.text()
                        logger.debug(f"Response: {response_text}")
                    
                    return success
                    
        except Exception as e:
            logger.warning(f"Webhook health check failed: {e}")
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
        Create standard webhook payload format.
        
        Args:
            event: Notification event to convert
            
        Returns:
            Dictionary representing standard payload
        """
        # Map notification levels to colors
        color_map = {
            NotificationLevel.INFO: "#36a64f",      # Green
            NotificationLevel.WARNING: "#ff9800",   # Orange
            NotificationLevel.CRITICAL: "#d32f2f"   # Red
        }
        
        # Create structured payload
        payload = {
            "timestamp": event.timestamp.isoformat(),
            "event_id": event.event_id,
            "level": event.level.value,
            "title": event.title,
            "message": event.message,
            "color": color_map.get(event.level, "#36a64f"),
            "scan_result": {
                "scan_id": event.scan_result.scan_id,
                "status": event.scan_result.status.value,
                "packages_scanned": event.scan_result.packages_scanned,
                "execution_time": getattr(event.scan_result, 'execution_duration_seconds', None)
            }
        }
        
        # Add affected packages if present
        if event.affected_packages:
            payload["affected_packages"] = [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "advisory_id": pkg.advisory_id,
                    "summary": pkg.summary
                }
                for pkg in event.affected_packages[:10]  # Limit to prevent huge payloads
            ]
            payload["critical_packages_count"] = len(event.affected_packages)
        
        # Add recommended actions
        if event.recommended_actions:
            payload["recommended_actions"] = event.recommended_actions
        
        return payload
    
    def _create_slack_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create Slack-compatible webhook payload.
        
        Args:
            event: Notification event to convert
            
        Returns:
            Dictionary representing Slack payload
        """
        # Map notification levels to Slack colors
        color_map = {
            NotificationLevel.INFO: "good",
            NotificationLevel.WARNING: "warning", 
            NotificationLevel.CRITICAL: "danger"
        }
        
        # Build fields for structured data
        fields = [
            {
                "title": "Scan ID",
                "value": event.scan_result.scan_id,
                "short": True
            },
            {
                "title": "Status",
                "value": event.scan_result.status.value.upper(),
                "short": True
            },
            {
                "title": "Packages Scanned",
                "value": str(event.scan_result.packages_scanned),
                "short": True
            }
        ]
        
        # Add critical packages info
        if event.affected_packages:
            fields.append({
                "title": "Critical Packages Found",
                "value": str(len(event.affected_packages)),
                "short": True
            })
            
            # Show first few package names
            package_names = [pkg.name for pkg in event.affected_packages[:5]]
            if len(event.affected_packages) > 5:
                package_names.append(f"... and {len(event.affected_packages) - 5} more")
            
            fields.append({
                "title": "Affected Packages",
                "value": ", ".join(package_names),
                "short": False
            })
        
        # Create Slack attachment
        attachment = {
            "color": color_map.get(event.level, "good"),
            "title": event.title,
            "text": event.message,
            "fields": fields,
            "footer": "Malifiscan Security Scanner",
            "ts": int(event.timestamp.timestamp())
        }
        
        return {
            "attachments": [attachment]
        }
    
    def _create_discord_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create Discord-compatible webhook payload.
        
        Args:
            event: Notification event to convert
            
        Returns:
            Dictionary representing Discord payload
        """
        # Map notification levels to Discord colors (decimal)
        color_map = {
            NotificationLevel.INFO: 3553599,    # Blue
            NotificationLevel.WARNING: 16753920,  # Orange
            NotificationLevel.CRITICAL: 15158332  # Red
        }
        
        # Build embed fields
        fields = [
            {
                "name": "Scan ID",
                "value": event.scan_result.scan_id,
                "inline": True
            },
            {
                "name": "Status", 
                "value": event.scan_result.status.value.upper(),
                "inline": True
            },
            {
                "name": "Packages Scanned",
                "value": str(event.scan_result.packages_scanned),
                "inline": True
            }
        ]
        
        # Add critical packages info
        if event.affected_packages:
            fields.append({
                "name": "Critical Packages Found",
                "value": str(len(event.affected_packages)),
                "inline": True
            })
            
            # Show package names
            package_names = [pkg.name for pkg in event.affected_packages[:5]]
            if len(event.affected_packages) > 5:
                package_names.append(f"... and {len(event.affected_packages) - 5} more")
            
            fields.append({
                "name": "Affected Packages",
                "value": ", ".join(package_names),
                "inline": False
            })
        
        # Add recommended actions
        if event.recommended_actions:
            actions_text = "\n".join([f"• {action}" for action in event.recommended_actions])
            fields.append({
                "name": "Recommended Actions",
                "value": actions_text,
                "inline": False
            })
        
        # Create Discord embed
        embed = {
            "title": event.title,
            "description": event.message,
            "color": color_map.get(event.level, 3553599),
            "fields": fields,
            "footer": {
                "text": "Malifiscan Security Scanner"
            },
            "timestamp": event.timestamp.isoformat()
        }
        
        return {
            "embeds": [embed]
        }
    
    def _create_custom_payload(self, event: NotificationEvent) -> Dict[str, Any]:
        """
        Create custom payload format (minimal structure for custom integrations).
        
        Args:
            event: Notification event to convert
            
        Returns:
            Dictionary representing custom payload
        """
        return {
            "event": {
                "id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "level": event.level.value,
                "title": event.title,
                "message": event.message
            },
            "scan": {
                "id": event.scan_result.scan_id,
                "status": event.scan_result.status.value,
                "packages_scanned": event.scan_result.packages_scanned,
                "critical_packages": len(event.affected_packages) if event.affected_packages else 0
            },
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem
                }
                for pkg in (event.affected_packages or [])[:20]
            ] if event.affected_packages else [],
            "actions": event.recommended_actions or []
        }
    
    def _create_test_payload(self) -> Dict[str, Any]:
        """
        Create test payload for health checks.
        
        Returns:
            Dictionary representing test payload
        """
        if self.payload_format == "slack":
            return {
                "text": "🔍 Malifiscan Webhook Health Check",
                "attachments": [{
                    "color": "good",
                    "text": "This is a test message to verify webhook connectivity.",
                    "footer": "Malifiscan Security Scanner"
                }]
            }
        elif self.payload_format == "discord":
            return {
                "embeds": [{
                    "title": "🔍 Malifiscan Webhook Health Check",
                    "description": "This is a test message to verify webhook connectivity.",
                    "color": 3553599,
                    "footer": {"text": "Malifiscan Security Scanner"}
                }]
            }
        else:
            return {
                "title": "🔍 Malifiscan Webhook Health Check",
                "message": "This is a test message to verify webhook connectivity.",
                "level": "info",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for webhook requests.
        
        Returns:
            Dictionary of HTTP headers
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Malifiscan-Security-Scanner/1.0"
        }
        
        # Add custom headers
        headers.update(self.custom_headers)
        
        return headers
    
    async def _send_with_retries(self, payload: Dict[str, Any]) -> bool:
        """
        Send payload to webhook with retry logic.
        
        Args:
            payload: Webhook payload
            
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
                        headers=self._get_headers()
                    ) as response:
                        
                        # Consider various success status codes
                        if response.status in [200, 201, 202, 204]:
                            return True
                        
                        # Log error details for debugging
                        response_text = await response.text()
                        logger.warning(f"Webhook returned HTTP {response.status}: {response_text}")
                        
                        # Some status codes indicate permanent failure, don't retry
                        if response.status in [400, 401, 403, 404, 405]:
                            logger.error(f"Permanent error from webhook: HTTP {response.status}")
                            return False
                        
                        # For other errors, we'll retry
                        if attempt < self.max_retries:
                            logger.debug(f"Retrying webhook notification (attempt {attempt + 1}/{self.max_retries})")
                            await asyncio.sleep(self.retry_delay)
                        
            except Exception as e:
                last_exception = e
                logger.warning(f"Webhook notification attempt {attempt + 1} failed: {e}")
                
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        # All attempts failed
        if last_exception:
            logger.error(f"All webhook notification attempts failed. Last error: {last_exception}")
        
        return False
    
    def __str__(self) -> str:
        """String representation of the notifier."""
        masked_url = self.webhook_url[:50] + "..." if len(self.webhook_url) > 50 else self.webhook_url
        return f"WebhookNotifier(url={masked_url}, format={self.payload_format})"