"""Core entities module."""

from .malicious_package import MaliciousPackage
from .notification_event import (
    NotificationChannel,
    NotificationEvent,
    NotificationLevel,
)
from .scan_result import ScanResult, ScanStatus

__all__ = [
    "MaliciousPackage",
    "ScanResult",
    "ScanStatus",
    "NotificationEvent",
    "NotificationLevel",
    "NotificationChannel",
]
