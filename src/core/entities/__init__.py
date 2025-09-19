"""Core entities module."""

from .malicious_package import MaliciousPackage
from .scan_result import ScanResult, ScanStatus
from .notification_event import NotificationEvent, NotificationLevel, NotificationChannel

__all__ = ["MaliciousPackage", "ScanResult", "ScanStatus", "NotificationEvent", "NotificationLevel", "NotificationChannel"]