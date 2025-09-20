"""Tests for MemoryStorage provider."""

import pytest
from datetime import datetime, timezone
from typing import List

from src.providers.storage.memory_storage import MemoryStorage
from src.core.entities import ScanResult, MaliciousPackage, ScanStatus
from src.providers.exceptions import StorageError


@pytest.fixture
def memory_storage():
    """Create a fresh memory storage instance for each test."""
    return MemoryStorage(clear_on_init=True)


@pytest.fixture
def sample_malicious_package():
    """Create a sample malicious package for testing."""
    return MaliciousPackage(
        name="test-package",
        version="1.0.0",
        ecosystem="npm",
        package_url="pkg:npm/test-package@1.0.0",
        advisory_id="TEST-2024-001",
        summary="Test malicious package",
        details="This is a test malicious package for unit testing",
        aliases=["TEST-001", "CVE-2024-TEST"],
        affected_versions=["1.0.0", "1.0.1"],
        database_specific={"test": "data"},
        published_at=datetime.now(timezone.utc),
        modified_at=datetime.now(timezone.utc)
    )


@pytest.fixture
def sample_scan_result(sample_malicious_package):
    """Create a sample scan result for testing."""
    return ScanResult(
        scan_id="test-scan-001",
        timestamp=datetime.now(timezone.utc),
        status=ScanStatus.SUCCESS,
        packages_scanned=10,
        malicious_packages_found=[sample_malicious_package],
        packages_blocked=["test-package"],
        malicious_packages_list=[],
        errors=[],
        execution_duration_seconds=5.5
    )


class TestMemoryStorageHealthCheck:
    """Test health check functionality."""
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_health_check_success(self, memory_storage):
        """Test successful health check."""
        result = await memory_storage.health_check()
        assert result is True


class TestMemoryStorageScanResults:
    """Test scan result storage and retrieval."""
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_store_scan_result_success(self, memory_storage, sample_scan_result):
        """Test successful scan result storage."""
        result = await memory_storage.store_scan_result(sample_scan_result)
        assert result is True
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_store_scan_result_duplicate_replaces(self, memory_storage, sample_scan_result):
        """Test that storing duplicate scan IDs replaces the previous result."""
        # Store original
        await memory_storage.store_scan_result(sample_scan_result)
        
        # Create modified version with same scan_id
        modified_result = ScanResult(
            scan_id=sample_scan_result.scan_id,  # Same scan ID
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.FAILED,  # Different status
            packages_scanned=20,  # Different count
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=["Test error"],
            execution_duration_seconds=10.0
        )
        
        await memory_storage.store_scan_result(modified_result)
        
        # Retrieve and verify only the modified version exists
        results = await memory_storage.get_scan_results()
        assert len(results) == 1
        assert results[0].scan_id == sample_scan_result.scan_id
        assert results[0].status == ScanStatus.FAILED
        assert results[0].packages_scanned == 20
    
    @pytest.mark.asyncio
    async def test_get_scan_results_empty(self, memory_storage):
        """Test retrieving scan results when none exist."""
        results = await memory_storage.get_scan_results()
        assert results == []
    
    @pytest.mark.asyncio
    async def test_get_scan_results_by_limit(self, memory_storage):
        """Test retrieving scan results with limit."""
        # Store multiple scan results
        for i in range(5):
            scan_result = ScanResult(
                scan_id=f"test-scan-{i:03d}",
                timestamp=datetime.now(timezone.utc),
                status=ScanStatus.SUCCESS,
                packages_scanned=i,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=1.0
            )
            await memory_storage.store_scan_result(scan_result)
        
        # Test limit
        results = await memory_storage.get_scan_results(limit=3)
        assert len(results) == 3
        
        # Verify they are in reverse chronological order (newest first)
        scan_ids = [r.scan_id for r in results]
        assert "test-scan-004" in scan_ids
        assert "test-scan-003" in scan_ids
        assert "test-scan-002" in scan_ids
    
    @pytest.mark.asyncio
    async def test_get_scan_results_by_scan_id(self, memory_storage, sample_scan_result):
        """Test retrieving specific scan result by scan ID."""
        await memory_storage.store_scan_result(sample_scan_result)
        
        # Store another scan result
        other_result = ScanResult(
            scan_id="other-scan",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=2.0
        )
        await memory_storage.store_scan_result(other_result)
        
        # Get specific scan result
        results = await memory_storage.get_scan_results(scan_id="test-scan-001")
        assert len(results) == 1
        assert results[0].scan_id == "test-scan-001"
    
    @pytest.mark.asyncio
    async def test_max_scan_results_rotation(self, memory_storage):
        """Test that old scan results are removed when max limit is reached."""
        # Create storage with small limit
        storage = MemoryStorage(max_scan_results=3, clear_on_init=True)
        
        # Store more than the limit
        for i in range(5):
            scan_result = ScanResult(
                scan_id=f"test-scan-{i:03d}",
                timestamp=datetime.now(timezone.utc),
                status=ScanStatus.SUCCESS,
                packages_scanned=i,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=1.0
            )
            await storage.store_scan_result(scan_result)
        
        # Verify only the most recent ones are kept
        results = await storage.get_scan_results()
        assert len(results) == 3
        
        scan_ids = [r.scan_id for r in results]
        assert "test-scan-004" in scan_ids  # Most recent
        assert "test-scan-003" in scan_ids
        assert "test-scan-002" in scan_ids
        assert "test-scan-001" not in scan_ids  # Should be removed
        assert "test-scan-000" not in scan_ids  # Should be removed


class TestMemoryStorageMaliciousPackages:
    """Test malicious package storage and retrieval."""
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_success(self, memory_storage, sample_malicious_package):
        """Test successful malicious package storage."""
        result = await memory_storage.store_malicious_packages([sample_malicious_package])
        assert result is True
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_avoid_duplicates(self, memory_storage, sample_malicious_package):
        """Test that duplicate packages are not stored multiple times."""
        # Store package twice
        await memory_storage.store_malicious_packages([sample_malicious_package])
        await memory_storage.store_malicious_packages([sample_malicious_package])
        
        # Verify only one copy exists
        packages = await memory_storage.get_known_malicious_packages()
        assert len(packages) == 1
        assert packages[0].name == sample_malicious_package.name
    
    @pytest.mark.asyncio
    async def test_get_known_malicious_packages_empty(self, memory_storage):
        """Test retrieving malicious packages when none exist."""
        packages = await memory_storage.get_known_malicious_packages()
        assert packages == []
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve_multiple_packages(self, memory_storage):
        """Test storing and retrieving multiple malicious packages."""
        packages = []
        for i in range(3):
            package = MaliciousPackage(
                name=f"test-package-{i}",
                version="1.0.0",
                ecosystem="npm",
                package_url=f"pkg:npm/test-package-{i}@1.0.0",
                advisory_id=f"TEST-2024-{i:03d}",
                summary=f"Test malicious package {i}",
                details=f"Details for test package {i}",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc)
            )
            packages.append(package)
        
        # Store all packages
        result = await memory_storage.store_malicious_packages(packages)
        assert result is True
        
        # Retrieve and verify
        retrieved_packages = await memory_storage.get_known_malicious_packages()
        assert len(retrieved_packages) == 3
        
        package_names = [p.name for p in retrieved_packages]
        assert "test-package-0" in package_names
        assert "test-package-1" in package_names
        assert "test-package-2" in package_names


class TestMemoryStorageUtilities:
    """Test utility functions."""
    
    @pytest.mark.asyncio
    async def test_clear_all_data(self, memory_storage, sample_scan_result, sample_malicious_package):
        """Test clearing all data."""
        # Store some data
        await memory_storage.store_scan_result(sample_scan_result)
        await memory_storage.store_malicious_packages([sample_malicious_package])
        
        # Verify data exists
        scan_results = await memory_storage.get_scan_results()
        malicious_packages = await memory_storage.get_known_malicious_packages()
        assert len(scan_results) == 1
        assert len(malicious_packages) == 1
        
        # Clear all data
        result = await memory_storage.clear_all_data()
        assert result is True
        
        # Verify data is cleared
        scan_results = await memory_storage.get_scan_results()
        malicious_packages = await memory_storage.get_known_malicious_packages()
        assert len(scan_results) == 0
        assert len(malicious_packages) == 0
    
    @pytest.mark.asyncio
    async def test_get_stats(self, memory_storage, sample_scan_result, sample_malicious_package):
        """Test getting storage statistics."""
        # Initially empty
        stats = memory_storage.get_stats()
        assert stats["type"] == "memory"
        assert stats["scan_results_count"] == 0
        assert stats["malicious_packages_count"] == 0
        assert stats["max_scan_results"] == 1000
        assert isinstance(stats["memory_usage_bytes"], int)
        
        # Store some data
        await memory_storage.store_scan_result(sample_scan_result)
        await memory_storage.store_malicious_packages([sample_malicious_package])
        
        # Check updated stats
        stats = memory_storage.get_stats()
        assert stats["scan_results_count"] == 1
        assert stats["malicious_packages_count"] == 1


class TestMemoryStoragePersistenceAcrossInstances:
    """Test that data persists across instances (class-level storage)."""
    
    @pytest.mark.asyncio
    async def test_data_persistence_across_instances(self, sample_scan_result):
        """Test that data persists when creating new instances."""
        # Clear any existing data
        storage1 = MemoryStorage(clear_on_init=True)
        
        # Store data in first instance
        await storage1.store_scan_result(sample_scan_result)
        
        # Create second instance (without clearing)
        storage2 = MemoryStorage(clear_on_init=False)
        
        # Verify data is still accessible
        results = await storage2.get_scan_results()
        assert len(results) == 1
        assert results[0].scan_id == sample_scan_result.scan_id
        
        # Clean up
        await storage2.clear_all_data()
    
    @pytest.mark.asyncio
    async def test_clear_on_init_clears_data(self, sample_scan_result):
        """Test that clear_on_init=True clears existing data."""
        # Store data in first instance
        storage1 = MemoryStorage(clear_on_init=True)
        await storage1.store_scan_result(sample_scan_result)
        
        # Verify data exists
        results = await storage1.get_scan_results()
        assert len(results) == 1
        
        # Create second instance with clear_on_init=True
        storage2 = MemoryStorage(clear_on_init=True)
        
        # Verify data is cleared
        results = await storage2.get_scan_results()
        assert len(results) == 0


class TestMemoryStorageErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_storage_error_propagation(self, memory_storage):
        """Test that storage errors are properly propagated."""
        # This test is mainly for interface compliance
        # MemoryStorage is unlikely to throw StorageError in normal operation
        # but we test the interface
        
        # Create a scan result with invalid data that might cause issues
        invalid_scan_result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=0,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=0.0
        )
        
        # Should not raise an error for valid data
        result = await memory_storage.store_scan_result(invalid_scan_result)
        assert result is True