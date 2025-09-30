"""Integration tests for the security scanner pipeline."""

from datetime import datetime
from unittest.mock import patch

import pytest

from src.core.entities import MaliciousPackage, ScanStatus
from src.core.usecases import SecurityScanner
from src.factories import ServiceFactory


class TestSecurityScannerIntegration:
    """Integration tests for the security scanner."""

    @pytest.fixture
    def test_scanner(self, test_config):
        """Create a test scanner with test configuration."""
        # Create service factory and scanner
        factory = ServiceFactory(test_config)
        scanner = SecurityScanner(
            packages_feed=factory.create_packages_feed(),
            registry_service=factory.create_packages_registry(),
            storage_service=factory.create_storage_service(),
            notification_service=factory.create_notification_service(),
        )

        return scanner

    @pytest.mark.asyncio
    async def test_scanner_with_mocked_services(self, test_scanner):
        """Test the scanner with mocked external services."""
        # Create test malicious package
        test_package = MaliciousPackage(
            name="malicious-test-pkg",
            version="1.0.0",
            ecosystem="PyPI",
            package_url="pkg:pypi/malicious-test-pkg@1.0.0",
            advisory_id="TEST-2023-0001",
            summary="Test malicious package",
            details="This is a test malicious package for integration testing",
            aliases=["CVE-TEST-1234"],
            affected_versions=["1.0.0"],
            database_specific={"severity": "HIGH"},
            published_at=datetime(2023, 1, 1),
            modified_at=datetime(2023, 1, 1),
        )

        # Mock the external services
        with (
            patch.object(
                test_scanner._packages_feed, "fetch_malicious_packages"
            ) as mock_fetch,
            patch.object(
                test_scanner._registry_service, "check_existing_packages"
            ) as mock_check,
            patch.object(
                test_scanner._registry_service, "block_packages"
            ) as mock_block,
        ):

            # Configure mocks
            mock_fetch.return_value = [test_package]
            mock_check.return_value = []  # No existing packages
            mock_block.return_value = []  # No packages blocked

            # Execute scan
            result = await test_scanner.execute_scan()

            # Verify results
            assert result.status == ScanStatus.SUCCESS
            assert len(result.malicious_packages_found) == 1
            assert result.malicious_packages_found[0].name == "malicious-test-pkg"

            # Verify service calls
            mock_fetch.assert_called_once()
            mock_check.assert_called_once_with([test_package])
            mock_block.assert_called_once_with([test_package])

    @pytest.mark.asyncio
    async def test_scanner_component_initialization(self, test_scanner):
        """Test scanner component initialization."""
        # Verify all services are properly initialized
        assert test_scanner._packages_feed is not None
        assert test_scanner._registry_service is not None
        assert test_scanner._storage_service is not None
        assert test_scanner._notification_service is not None
