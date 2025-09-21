"""Tests for core entities."""

import pytest
from datetime import datetime

from src.core.entities import MaliciousPackage, ScanResult, ScanStatus, NotificationEvent, NotificationLevel, NotificationChannel


class TestMaliciousPackage:
    """Tests for MaliciousPackage entity."""
    
    def test_create_malicious_package(self):
        """Test creating a malicious package."""
        package = MaliciousPackage(
            name="test-package",
            version="1.0.0",
            ecosystem="PyPI",
            package_url="pkg:pypi/test-package@1.0.0",
            advisory_id="OSV-2023-0001",
            summary="Test malicious package",
            details="Test details",
            aliases=["CVE-2023-1234"],
            affected_versions=["1.0.0"],
            database_specific={"severity": "HIGH"},
            published_at=datetime(2023, 1, 1),
            modified_at=datetime(2023, 1, 2)
        )
        
        assert package.name == "test-package"
        assert package.version == "1.0.0"
        assert package.ecosystem == "PyPI"
        assert package.package_identifier == "PyPI:test-package:1.0.0"
    
    def test_package_identifier_without_version(self):
        """Test package identifier without version."""
        package = MaliciousPackage(
            name="test-package",
            version=None,
            ecosystem="PyPI",
            package_url=None,
            advisory_id=None,
            summary=None,
            details=None,
            aliases=[],
            affected_versions=[],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        
        assert package.package_identifier == "PyPI:test-package"
    
    def test_matches_package(self):
        """Test package matching logic."""
        package = MaliciousPackage(
            name="test-package",
            version=None,
            ecosystem="PyPI",
            package_url=None,
            advisory_id=None,
            summary=None,
            details=None,
            aliases=[],
            affected_versions=["1.0.0", "1.0.1"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        
        # Should match name regardless of case
        assert package.matches_package("test-package")
        assert package.matches_package("Test-Package")
        assert not package.matches_package("other-package")
        
        # Should match affected versions
        assert package.matches_package("test-package", "1.0.0")
        assert package.matches_package("test-package", "1.0.1")
        assert not package.matches_package("test-package", "2.0.0")
    
    def test_validation_errors(self):
        """Test validation errors for invalid data."""
        with pytest.raises(ValueError, match="Package name cannot be empty"):
            MaliciousPackage(
                name="",
                version=None,
                ecosystem="PyPI",
                package_url=None,
                advisory_id=None,
                summary=None,
                details=None,
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=None,
                modified_at=None
            )
        
        with pytest.raises(ValueError, match="Ecosystem cannot be empty"):
            MaliciousPackage(
                name="test-package",
                version=None,
                ecosystem="",
                package_url=None,
                advisory_id=None,
                summary=None,
                details=None,
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=None,
                modified_at=None
            )


class TestScanResult:
    """Tests for ScanResult entity."""
    
    def test_create_scan_result(self, sample_malicious_package):
        """Test creating a scan result."""
        scan_result = ScanResult(
            scan_id="test-scan",
            timestamp=datetime(2023, 1, 1),
            status=ScanStatus.SUCCESS,
            packages_scanned=100,
            malicious_packages_found=[sample_malicious_package],
            packages_blocked=["PyPI:malicious-pkg:1.0.0"],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=30.5
        )
        
        assert scan_result.scan_id == "test-scan"
        assert scan_result.status == ScanStatus.SUCCESS
        assert scan_result.packages_scanned == 100
        assert len(scan_result.malicious_packages_found) == 1
        assert scan_result.is_successful
        assert scan_result.has_new_threats
        assert scan_result.new_threats_count == 1
    
    def test_no_new_threats(self, sample_malicious_package):
        """Test scan result with no new threats."""
        scan_result = ScanResult(
            scan_id="test-scan",
            timestamp=datetime(2023, 1, 1),
            status=ScanStatus.SUCCESS,
            packages_scanned=100,
            malicious_packages_found=[sample_malicious_package],
            packages_blocked=[],
            malicious_packages_list=[sample_malicious_package],
            errors=[],
            execution_duration_seconds=30.5
        )
        
        assert not scan_result.has_new_threats
        assert scan_result.new_threats_count == 0


class TestNotificationEvent:
    """Tests for NotificationEvent entity."""
    
    def test_create_threat_notification_with_new_threats(self, sample_scan_result):
        """Test creating notification for new threats."""
        event = NotificationEvent.create_threat_notification(
            event_id="test-event",
            scan_result=sample_scan_result,
            channels=[NotificationChannel.SLACK],
            metadata={"test": True}
        )
        
        assert event.event_id == "test-event"
        assert event.level == NotificationLevel.CRITICAL
        assert "New Malicious Package" in event.title
        assert len(event.affected_packages) == 1
        assert NotificationChannel.SLACK in event.channels
        # recommended_actions field was removed - check that payload includes scan details instead
        payload = event.to_standard_payload()
        assert "scan_result" in payload
        assert payload["scan_result"]["status"] == "success"
    
    def test_create_threat_notification_no_new_threats(self, sample_malicious_package):
        """Test creating notification with no new threats."""
        scan_result = ScanResult(
            scan_id="test-scan",
            timestamp=datetime(2023, 1, 1),
            status=ScanStatus.SUCCESS,
            packages_scanned=0,  # Fixed: no packages scanned to match "no threats" scenario
            malicious_packages_found=[sample_malicious_package],
            packages_blocked=[],
            malicious_packages_list=[sample_malicious_package],
            errors=[],
            execution_duration_seconds=30.5
        )
        
        event = NotificationEvent.create_threat_notification(
            event_id="test-event",
            scan_result=scan_result,
            channels=[NotificationChannel.EMAIL]
        )
        
        assert event.level == NotificationLevel.INFO
        assert "No New Threats" in event.title
        assert len(event.affected_packages) == 0
        # recommended_actions field was removed - check that payload includes useful information instead
        payload = event.to_standard_payload()
        assert "scan_result" in payload
        assert payload["scan_result"]["packages_scanned"] == 0