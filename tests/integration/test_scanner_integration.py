"""Integration tests for the security scanner pipeline."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch
from datetime import datetime

from src.config import ConfigLoader
from src.core.entities import MaliciousPackage, ScanStatus
from src.core.usecases import SecurityScanner
from src.factories import ServiceFactory


class TestSecurityScannerIntegration:
    """Integration tests for the security scanner."""

    @pytest.fixture
    def test_scanner(self):
        """Create a test scanner with file-based configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create configuration file
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text(f"""
environment: test

packages_feed:
  type: osv
  enabled: true
  config:
    base_url: https://osv-vulnerabilities.storage.googleapis.com
    bucket_name: osv-vulnerabilities
    hours_back: 48

packages_registry:
  type: jfrog
  enabled: true
  jfrog_base_url: https://test-jfrog.example.com

storage_service:
  type: file
  enabled: true
  config:
    data_directory: {temp_dir}/data
""")
            
            # Create environment file
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("""
OSV_API_BASE_URL=https://osv-vulnerabilities.storage.googleapis.com
JFROG_BASE_URL=https://test-jfrog.example.com
JFROG_API_KEY=test-api-key
""")
            
            # Load configuration  
            config_loader = ConfigLoader(str(config_file), str(env_file))
            config = config_loader.load()
            
            # Create service factory and scanner
            factory = ServiceFactory(config)
            scanner = SecurityScanner(
                packages_feed=factory.create_packages_feed(),
                registry_service=factory.create_packages_registry(),
                storage_service=factory.create_storage_service(),
                notification_service=factory.create_notification_service()
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
            modified_at=datetime(2023, 1, 1)
        )

        # Mock the external services
        with patch.object(test_scanner._packages_feed, 'fetch_malicious_packages') as mock_fetch, \
             patch.object(test_scanner._registry_service, 'check_existing_packages') as mock_check, \
             patch.object(test_scanner._registry_service, 'block_packages') as mock_block:
            
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