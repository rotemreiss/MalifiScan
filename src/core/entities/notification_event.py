"""Notification event entity."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

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
    channels: List[NotificationChannel]
    metadata: dict
    registry_type: Optional[str] = None
    registry_url: Optional[str] = None

    @classmethod
    def create_threat_notification(
        cls,
        event_id: str,
        scan_result: ScanResult,
        channels: List[NotificationChannel],
        metadata: Optional[dict] = None,
    ) -> "NotificationEvent":
        """Create a threat detection notification."""
        new_threats = [
            pkg
            for pkg in scan_result.malicious_packages_found
            if pkg not in scan_result.malicious_packages_list
        ]

        level = NotificationLevel.CRITICAL if new_threats else NotificationLevel.INFO

        if new_threats:
            title = f"🚨 {len(new_threats)} New Malicious Package(s) Detected"
            message = (
                f"Security scan detected {len(new_threats)} new malicious package(s) "
                f"and blocked them in the registry. Immediate attention required."
            )
        else:
            title = "✅ Security Scan Completed - No New Threats"
            message = (
                f"Routine security scan completed successfully. "
                f"Scanned {scan_result.packages_scanned} packages. "
                f"No new threats detected."
            )

        return cls(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc),
            level=level,
            title=title,
            message=message,
            scan_result=scan_result,
            affected_packages=new_threats,
            channels=channels,
            metadata=metadata or {},
        )

    def to_standard_payload(self) -> Dict[str, Any]:
        """Convert notification event to standardized payload format for all providers."""
        payload = {
            "title": self.title,
            "message": self.message,
            "level": self.level.value,
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
        }

        # Add scan result information
        if self.scan_result:
            payload["scan_result"] = {
                "scan_id": self.scan_result.scan_id,
                "status": self.scan_result.status.value,
                "packages_scanned": self.scan_result.packages_scanned,
                "malicious_packages_found": len(self.affected_packages or []),
                "errors": [str(error) for error in (self.scan_result.errors or [])],
                "execution_duration_seconds": self.scan_result.execution_duration_seconds,
            }

        # Add registry information
        if self.registry_type or self.registry_url:
            payload["registry"] = {}
            if self.registry_type:
                payload["registry"]["type"] = self.registry_type
            if self.registry_url:
                payload["registry"]["url"] = self.registry_url

        # Add affected packages details
        if self.affected_packages:
            payload["affected_packages"] = []
            for pkg in self.affected_packages:
                package_data = {
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "package_url": pkg.package_url,
                    "advisory_id": pkg.advisory_id,
                    "summary": pkg.summary,
                    "severity": (
                        pkg.database_specific.get("severity", "UNKNOWN")
                        if pkg.database_specific
                        else "UNKNOWN"
                    ),
                    "published_at": (
                        pkg.published_at.isoformat() if pkg.published_at else None
                    ),
                    "affected_versions": pkg.affected_versions or [],
                }
                if pkg.aliases:
                    package_data["aliases"] = pkg.aliases
                payload["affected_packages"].append(package_data)

        return payload
