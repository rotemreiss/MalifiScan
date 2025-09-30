"""Test configuration and utilities."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from src.core.entities import (
    MaliciousPackage,
    NotificationChannel,
    NotificationEvent,
    NotificationLevel,
    ScanResult,
    ScanStatus,
)


@pytest.fixture
def test_malicious_packages():
    """Create a list of test malicious packages with various ecosystems."""
    return [
        MaliciousPackage(
            name="test-critical-npm",
            version="1.0.0",
            ecosystem="npm",
            package_url="pkg:npm/test-critical-npm@1.0.0",
            advisory_id="TEST-CRITICAL-001",
            summary="Critical test package",
            details="Critical vulnerability for testing",
            aliases=["CVE-2024-CRIT-TEST"],
            affected_versions=["1.0.0", "1.1.0"],
            database_specific={"severity": "CRITICAL"},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
        MaliciousPackage(
            name="test-safe-npm",
            version="2.0.0",
            ecosystem="npm",
            package_url="pkg:npm/test-safe-npm@2.0.0",
            advisory_id="TEST-SAFE-001",
            summary="Safe test package",
            details="Non-matching versions for testing",
            aliases=["CVE-2024-SAFE-TEST"],
            affected_versions=["2.0.0"],
            database_specific={"severity": "LOW"},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
        MaliciousPackage(
            name="test-pypi-pkg",
            version="3.0.0",
            ecosystem="PyPI",
            package_url="pkg:pypi/test-pypi-pkg@3.0.0",
            advisory_id="TEST-PYPI-001",
            summary="PyPI test package",
            details="PyPI ecosystem test package",
            aliases=["CVE-2024-PYPI-TEST"],
            affected_versions=["3.0.0", "3.1.0"],
            database_specific={"severity": "HIGH"},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
    ]


@pytest.fixture
def sample_malicious_package(test_malicious_packages):
    """Get a PyPI malicious package for single-package tests."""
    # Return the PyPI package (index 2)
    return test_malicious_packages[2]


@pytest.fixture
def sample_npm_malicious_package(test_malicious_packages):
    """Get an npm malicious package for npm-specific tests."""
    # Return the first npm package (index 0)
    return test_malicious_packages[0]


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
        execution_duration_seconds=1.5,
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
        execution_duration_seconds=1.5,
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
        execution_duration_seconds=2.3,
    )


@pytest.fixture
def sample_notification_event(sample_scan_result):
    """Create a sample notification event for testing."""
    return NotificationEvent.create_threat_notification(
        event_id="notif-123",
        scan_result=sample_scan_result,
        channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
        metadata={"test": True},
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
        metadata={"test": True},
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
        registry_url="https://test.jfrog.io",
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
        registry_url="https://test.jfrog.io",
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
        metadata={},
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


@pytest.fixture
def test_config_path():
    """Get path to test configuration file."""
    from pathlib import Path

    config_path = Path(__file__).parent / "config.tests.yaml"
    return str(config_path)


@pytest.fixture
def test_config(test_config_path):
    """Load test configuration for integration tests."""
    from src.config.config_loader import ConfigLoader

    config_loader = ConfigLoader(
        config_file=test_config_path,
        local_config_file=None,  # Disable local config overrides for tests
        load_env_file=False,  # Disable .env file loading for tests
        use_env_vars=False,  # Disable environment variable overrides for tests
    )
    return config_loader.load()


@pytest.fixture
def memory_feed_with_packages(test_malicious_packages):
    """Create a memory feed with test packages."""
    from src.providers.feeds.memory_feed import MemoryFeed

    return MemoryFeed(packages=test_malicious_packages)


@pytest.fixture
def null_registry_with_packages(test_registry_packages):
    """Create a null registry with simulated test packages."""
    from src.providers.registries.null_registry import NullRegistry

    return NullRegistry(packages=test_registry_packages)


@pytest.fixture
def memory_storage():
    """Create a memory storage instance for testing."""
    from src.providers.storage.memory_storage import MemoryStorage

    return MemoryStorage(clear_on_init=True)


@pytest.fixture
def null_notifier():
    """Create a null notifier for testing."""
    from src.providers.notifications.null_notifier import NullNotifier

    return NullNotifier()


@pytest.fixture
def test_registry_packages():
    """Create a list of simulated registry packages for testing."""
    return [
        # This package has overlapping versions with test-critical-npm
        MaliciousPackage(
            name="test-critical-npm",
            version="1.0.0",
            ecosystem="npm",
            package_url="pkg:npm/test-critical-npm@1.0.0",
            advisory_id="REGISTRY-SIM-001",
            summary="Simulated registry package",
            details="Simulated package in registry",
            aliases=[],
            affected_versions=[
                "1.0.0",
                "1.2.0",
                "1.3.0",
            ],  # Contains overlap with malicious
            database_specific={},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
        # This package has NO overlapping versions with test-safe-npm
        MaliciousPackage(
            name="test-safe-npm",
            version="2.1.0",
            ecosystem="npm",
            package_url="pkg:npm/test-safe-npm@2.1.0",
            advisory_id="REGISTRY-SIM-002",
            summary="Simulated safe registry package",
            details="Safe simulated package in registry",
            aliases=[],
            affected_versions=["2.1.0", "2.2.0"],  # No overlap with malicious versions
            database_specific={},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
        # Extra package not in malicious list
        MaliciousPackage(
            name="extra-registry-pkg",
            version="4.0.0",
            ecosystem="npm",
            package_url="pkg:npm/extra-registry-pkg@4.0.0",
            advisory_id="REGISTRY-SIM-003",
            summary="Extra simulated registry package",
            details="Extra package only in registry",
            aliases=[],
            affected_versions=["4.0.0"],
            database_specific={},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        ),
    ]
