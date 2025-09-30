"""Notification testing use case."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from src.core.entities import (
    MaliciousPackage,
    NotificationChannel,
    NotificationEvent,
    NotificationLevel,
    ScanResult,
    ScanStatus,
)
from src.core.interfaces import NotificationService

logger = logging.getLogger(__name__)


class NotificationTestingUseCase:
    """Use case for testing notification functionality."""

    def __init__(self, notification_service: NotificationService):
        """
        Initialize notification testing use case.

        Args:
            notification_service: Notification service to test
        """
        self.notification_service = notification_service
        self.logger = logger

    async def test_notification_service(
        self, include_malicious: bool = False
    ) -> Dict[str, Any]:
        """
        Test notification service with various scenarios.

        Args:
            include_malicious: Whether to include malicious package test scenario

        Returns:
            Dictionary containing test results
        """
        try:
            self.logger.debug("Starting notification service test")

            # Step 1: Health check
            health_result = await self._test_health_check()
            if not health_result["success"]:
                return health_result

            # Step 2: Send test notification
            if include_malicious:
                test_result = await self._send_malicious_package_test()
            else:
                test_result = await self._send_basic_test()

            return test_result

        except Exception as e:
            self.logger.error(f"Notification testing failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "health_check": False,
                "notification_sent": False,
            }

    async def _test_health_check(self) -> Dict[str, Any]:
        """
        Test notification service health check.

        Returns:
            Health check result
        """
        try:
            self.logger.debug("Testing notification service health")
            is_healthy = await self.notification_service.health_check()

            if is_healthy:
                self.logger.debug("Notification service health check passed")
                return {"success": True, "healthy": True}
            else:
                self.logger.warning("Notification service health check failed")
                return {
                    "success": False,
                    "healthy": False,
                    "error": "Health check failed",
                }

        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            return {
                "success": False,
                "healthy": False,
                "error": f"Health check error: {str(e)}",
            }

    async def _send_basic_test(self) -> Dict[str, Any]:
        """
        Send basic test notification.

        Returns:
            Test result
        """
        try:
            self.logger.debug("Sending basic test notification")

            # Create basic test notification event
            test_event = self._create_basic_test_event()

            # Send notification
            success = await self.notification_service.send_notification(test_event)

            result = {
                "success": success,
                "notification_sent": success,
                "healthy": True,  # Health check already passed if we got here
                "test_type": "basic",
                "event_id": test_event.event_id,
            }

            if success:
                self.logger.debug("Basic test notification sent successfully")
            else:
                self.logger.warning("Basic test notification failed to send")
                result["error"] = "Failed to send test notification"

            return result

        except Exception as e:
            self.logger.error(f"Basic test notification error: {e}")
            return {
                "success": False,
                "notification_sent": False,
                "healthy": True,  # Health check already passed if we got here
                "test_type": "basic",
                "error": f"Test notification error: {str(e)}",
            }

    async def _send_malicious_package_test(self) -> Dict[str, Any]:
        """
        Send malicious package test notification.

        Returns:
            Test result
        """
        try:
            self.logger.debug("Sending malicious package test notification")

            # Create malicious package test notification event
            test_event = self._create_malicious_package_test_event()

            # Send notification
            success = await self.notification_service.send_notification(test_event)

            result = {
                "success": success,
                "notification_sent": success,
                "healthy": True,  # Health check already passed if we got here
                "test_type": "malicious_package",
                "event_id": test_event.event_id,
                "affected_packages_count": len(test_event.affected_packages),
            }

            if success:
                self.logger.debug(
                    "Malicious package test notification sent successfully"
                )
            else:
                self.logger.warning(
                    "Malicious package test notification failed to send"
                )
                result["error"] = "Failed to send malicious package test notification"

            return result

        except Exception as e:
            self.logger.error(f"Malicious package test notification error: {e}")
            return {
                "success": False,
                "notification_sent": False,
                "healthy": True,  # Health check already passed if we got here
                "test_type": "malicious_package",
                "error": f"Malicious package test notification error: {str(e)}",
            }

    def _create_basic_test_event(self) -> NotificationEvent:
        """
        Create basic test notification event.

        Returns:
            NotificationEvent for basic testing
        """
        # Create basic test scan result
        test_scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=1.5,
        )

        # Create basic test notification event
        return NotificationEvent(
            event_id=f"test-{uuid.uuid4()}",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.INFO,
            title="🧪 Malifiscan Notification Test",
            message="This is a test notification to verify that the notification system is working correctly. If you receive this message, your notification configuration is properly set up.",
            scan_result=test_scan_result,
            affected_packages=[],
            channels=[NotificationChannel.WEBHOOK],
            metadata={
                "test": True,
                "source": "malifiscan_cli",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            registry_type="test",
            registry_url="test://cli-notification-test",
        )

    def _create_malicious_package_test_event(self) -> NotificationEvent:
        """
        Create malicious package test notification event.

        Returns:
            NotificationEvent for malicious package testing
        """
        # Create test malicious package
        test_malicious_package = MaliciousPackage(
            name="mal-test-pack",
            version="9.9.9",
            ecosystem="npm",
            package_url="https://npmjs.com/package/mal-test-pack",
            advisory_id="CLI-TEST-2025-001",
            summary="Test malicious package for notification testing",
            details="This is a test malicious package created for testing notification functionality. It simulates a critical security vulnerability.",
            aliases=["GHSA-test-9999", "CVE-2025-99999"],
            affected_versions=["9.9.9"],
            database_specific={
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "cwe_ids": ["CWE-78", "CWE-94"],
                "impact": "Remote code execution",
            },
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        )

        # Create scan result with malicious package found
        test_scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=[test_malicious_package],
            packages_blocked=[],
            malicious_packages_list=[test_malicious_package],  # Found in registry
            errors=[],
            execution_duration_seconds=3.2,
        )

        # Create critical test notification event
        return NotificationEvent(
            event_id=f"test-malicious-{uuid.uuid4()}",
            timestamp=datetime.now(timezone.utc),
            level=NotificationLevel.CRITICAL,
            title="🚨 CRITICAL: Malicious Package Test Alert",
            message=f"CRITICAL SECURITY ALERT: Test malicious package '{test_malicious_package.name}@{test_malicious_package.version}' detected in registry. This is a test notification mimicking a real security incident.",
            scan_result=test_scan_result,
            affected_packages=[test_malicious_package],
            channels=[NotificationChannel.WEBHOOK],
            metadata={
                "test": True,
                "malicious_test": True,
                "source": "malifiscan_cli",
                "package_name": test_malicious_package.name,
                "package_version": test_malicious_package.version,
                "severity": "CRITICAL",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            registry_type="test",
            registry_url="test://cli-malicious-package-test",
        )
