"""Test configuration and utilities."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone

from src.core.entities import MaliciousPackage, ScanResult, ScanStatus, NotificationEvent, NotificationLevel, NotificationChannel


@pytest.fixture
def sample_malicious_package():
    """Create a sample malicious package for testing."""
    return MaliciousPackage(
        name="malicious-pkg",
        version="1.0.0",
        ecosystem="PyPI",
        package_url="pkg:pypi/malicious-pkg@1.0.0",
        advisory_id="OSV-2023-0001",
        summary="Malicious package with backdoor",
        details="This package contains a backdoor that steals credentials",
        aliases=["CVE-2023-1234"],
        affected_versions=["1.0.0", "1.0.1"],
        database_specific={"severity": "HIGH"},
        published_at=datetime(2023, 1, 1, 12, 0, 0),
        modified_at=datetime(2023, 1, 2, 12, 0, 0)
    )


@pytest.fixture
def sample_npm_malicious_package():
    """Create a sample npm malicious package for testing."""
    return MaliciousPackage(
        name="test-package",
        version="1.0.0",
        ecosystem="npm",
        package_url="https://npmjs.com/package/test-package",
        advisory_id="TEST-2024-001",
        summary="Test malicious package",
        details="Test vulnerability details",
        aliases=["CVE-2024-TEST"],
        affected_versions=["1.0.0"],
        database_specific={"severity": "HIGH"},
        published_at=datetime.now(timezone.utc),
        modified_at=datetime.now(timezone.utc)
    )


@pytest.fixture
def sample_scan_result(sample_malicious_package):
    """Create a sample scan result for testing."""
    return ScanResult(
        scan_id="test-scan-123",
        timestamp=datetime(2023, 1, 1, 12, 0, 0),
        status=ScanStatus.SUCCESS,
        packages_scanned=100,
        malicious_packages_found=[sample_malicious_package],
        packages_blocked=["PyPI:malicious-pkg:1.0.0"],
        malicious_packages_list=[],
        errors=[],
        execution_duration_seconds=1.5
    )


@pytest.fixture
def clean_scan_result():
    """Create a scan result with no malicious packages found."""
    return ScanResult(
        scan_id="test-scan-clean-123",
        timestamp=datetime.now(timezone.utc),
        status=ScanStatus.SUCCESS,
        packages_scanned=10,
        malicious_packages_found=[],
        packages_blocked=[],
        malicious_packages_list=[],
        errors=[],
        execution_duration_seconds=1.5
    )


@pytest.fixture
def critical_scan_result(sample_npm_malicious_package):
    """Create a scan result with critical malicious packages found."""
    return ScanResult(
        scan_id="test-scan-critical",
        timestamp=datetime.now(timezone.utc),
        status=ScanStatus.SUCCESS,
        packages_scanned=10,
        malicious_packages_found=[sample_npm_malicious_package],
        packages_blocked=[],
        malicious_packages_list=[sample_npm_malicious_package],
        errors=[],
        execution_duration_seconds=2.3
    )


@pytest.fixture 
def sample_notification_event(sample_scan_result):
    """Create a sample notification event for testing."""
    return NotificationEvent.create_threat_notification(
        event_id="notif-123",
        scan_result=sample_scan_result,
        channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
        metadata={"test": True}
    )


@pytest.fixture
def info_notification_event(clean_scan_result):
    """Create an info-level notification event."""
    return NotificationEvent(
        event_id="test-event-123",
        timestamp=datetime.now(timezone.utc),
        level=NotificationLevel.INFO,
        title="✅ Scan Complete",
        message="Security scan completed successfully",
        scan_result=clean_scan_result,
        affected_packages=None,
        channels=[NotificationChannel.WEBHOOK],
        metadata={"test": True}
    )


@pytest.fixture
def warning_notification_event(clean_scan_result):
    """Create a warning-level notification event."""
    return NotificationEvent(
        event_id="test-event-warning",
        timestamp=datetime.now(timezone.utc),
        level=NotificationLevel.WARNING,
        title="⚠️ Warning Alert",
        message="Warning detected",
        scan_result=clean_scan_result,
        affected_packages=None,
        channels=[NotificationChannel.WEBHOOK],
        metadata={},
        registry_type="jfrog",
        registry_url="https://test.jfrog.io"
    )


@pytest.fixture
def critical_notification_event(critical_scan_result, sample_npm_malicious_package):
    """Create a critical-level notification event with affected packages."""
    return NotificationEvent(
        event_id="test-event-critical",
        timestamp=datetime.now(timezone.utc),
        level=NotificationLevel.CRITICAL,
        title="🚨 Critical Security Alert",
        message="Malicious package detected",
        scan_result=critical_scan_result,
        affected_packages=[sample_npm_malicious_package],
        channels=[NotificationChannel.WEBHOOK],
        metadata={"test": True},
        registry_type="jfrog", 
        registry_url="https://test.jfrog.io"
    )


@pytest.fixture
def basic_notification_event(clean_scan_result):
    """Create a basic notification event for testing retry logic and simple scenarios."""
    return NotificationEvent(
        event_id="test-event-basic",
        timestamp=datetime.now(timezone.utc),
        level=NotificationLevel.INFO,
        title="Test Notification",
        message="Test message",
        scan_result=clean_scan_result,
        affected_packages=None,
        channels=[NotificationChannel.WEBHOOK],
        metadata={}
    )


@pytest.fixture
def mock_packages_feed():
    """Create a mock packages feed."""
    mock = AsyncMock()
    mock.fetch_malicious_packages.return_value = []
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_packages_registry():
    """Create a mock packages registry."""
    mock = AsyncMock()
    mock.block_packages.return_value = []
    mock.check_existing_packages.return_value = []
    mock.unblock_packages.return_value = []
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_notification_service():
    """Create a mock notification service."""
    mock = AsyncMock()
    mock.send_notification.return_value = True
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def mock_storage_service():
    """Create a mock storage service."""
    mock = AsyncMock()
    mock.store_scan_result.return_value = True
    mock.get_scan_results.return_value = []
    mock.get_known_malicious_packages.return_value = []
    mock.store_malicious_packages.return_value = True
    mock.health_check.return_value = True
    return mock


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


class AsyncIterator:
    """Helper class for async iteration in tests."""
    
    def __init__(self, items):
        self.items = iter(items)
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        try:
            return next(self.items)
        except StopIteration:
            raise StopAsyncIteration