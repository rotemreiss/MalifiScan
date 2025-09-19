"""Test configuration and utilities."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from typing import List

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
def sample_scan_result(sample_malicious_package):
    """Create a sample scan result for testing."""
    return ScanResult(
        scan_id="test-scan-123",
        timestamp=datetime(2023, 1, 1, 12, 0, 0),
        status=ScanStatus.SUCCESS,
        packages_scanned=100,
        malicious_packages_found=[sample_malicious_package],
        packages_blocked=["PyPI:malicious-pkg:1.0.0"],
        malicious_packages_list=[],  # Updated field name
        errors=[],
        execution_duration_seconds=30.5
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