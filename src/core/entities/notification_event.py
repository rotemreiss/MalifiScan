"""Notification event entity."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from .malicious_package import MaliciousPackage
from .scan_result import ScanResult


class NotificationLevel(Enum):
    """Notification severity level."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class NotificationChannel(Enum):
    """Notification delivery channel."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"


@dataclass(frozen=True)
class NotificationEvent:
    """Represents a notification event to be sent to SOC."""
    
    event_id: str
    timestamp: datetime
    level: NotificationLevel
    title: str
    message: str
    scan_result: ScanResult
    affected_packages: List[MaliciousPackage]
    recommended_actions: List[str]
    channels: List[NotificationChannel]
    metadata: dict
    
    @classmethod
    def create_threat_notification(
        cls,
        event_id: str,
        scan_result: ScanResult,
        channels: List[NotificationChannel],
        metadata: Optional[dict] = None
    ) -> "NotificationEvent":
        """Create a threat detection notification."""
        new_threats = [
            pkg for pkg in scan_result.malicious_packages_found
            if pkg not in scan_result.malicious_packages_list
        ]
        
        level = NotificationLevel.CRITICAL if new_threats else NotificationLevel.INFO
        
        if new_threats:
            title = f"🚨 {len(new_threats)} New Malicious Package(s) Detected"
            message = (
                f"Security scan detected {len(new_threats)} new malicious package(s) "
                f"and blocked them in the registry. Immediate attention required."
            )
            actions = [
                "Review blocked packages in the registry",
                "Investigate if any of these packages were previously downloaded",
                "Update security policies if needed",
                "Monitor for additional related threats"
            ]
        else:
            title = "✅ Security Scan Completed - No New Threats"
            message = (
                f"Routine security scan completed successfully. "
                f"Scanned {scan_result.packages_scanned} packages. "
                f"No new threats detected."
            )
            actions = ["Continue monitoring"]
        
        return cls(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc),
            level=level,
            title=title,
            message=message,
            scan_result=scan_result,
            affected_packages=new_threats,
            recommended_actions=actions,
            channels=channels,
            metadata=metadata or {}
        )