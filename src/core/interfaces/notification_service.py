"""Notification service interface."""

from abc import ABC, abstractmethod

from src.core.entities import NotificationEvent


class NotificationService(ABC):
    """Abstract interface for notification providers."""
    
    @abstractmethod
    async def send_notification(self, event: NotificationEvent) -> bool:
        """
        Send a notification event to the configured channels.
        
        Args:
            event: The notification event to send
            
        Returns:
            True if notification was sent successfully, False otherwise
            
        Raises:
            NotificationError: If notification delivery fails
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the notification service is healthy and accessible.
        
        Returns:
            True if service is healthy, False otherwise
        """
        pass