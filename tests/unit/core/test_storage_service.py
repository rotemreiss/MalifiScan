"""Tests for storage service interface and implementations."""

import pytest
from typing import List, Optional
from datetime import datetime, timezone

from src.core.interfaces.storage_service import StorageService
from src.core.entities import (
    ScanResult, ScanStatus, MaliciousPackage
)


class MockStorageService(StorageService):
    """Mock implementation of StorageService for testing."""
    
    def __init__(self):
        self.stored_scan_results = []
        self.stored_malicious_packages = []
        self.healthy = True
        self.store_scan_result_call_count = 0
        self.get_scan_results_call_count = 0
        self.get_known_malicious_packages_call_count = 0
        self.store_malicious_packages_call_count = 0
        self.health_check_call_count = 0
        self.should_raise_error = False
        self.error_message = "Mock error"
        self.store_success = True
        
    async def store_scan_result(self, scan_result: ScanResult) -> bool:
        """Mock implementation of store_scan_result."""
        self.store_scan_result_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        if self.store_success:
            self.stored_scan_results.append(scan_result)
            return True
        else:
            return False
    
    async def get_scan_results(
        self, 
        limit: Optional[int] = None,
        scan_id: Optional[str] = None
    ) -> List[ScanResult]:
        """Mock implementation of get_scan_results."""
        self.get_scan_results_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        results = self.stored_scan_results.copy()
        
        # Filter by scan_id if provided
        if scan_id is not None:
            results = [result for result in results if result.scan_id == scan_id]
        
        # Apply limit if provided
        if limit is not None:
            results = results[:limit]
        
        return results
    
    async def get_known_malicious_packages(self) -> List[MaliciousPackage]:
        """Mock implementation of get_known_malicious_packages."""
        self.get_known_malicious_packages_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        return self.stored_malicious_packages.copy()
    
    async def store_malicious_packages(self, packages: List[MaliciousPackage]) -> bool:
        """Mock implementation of store_malicious_packages."""
        self.store_malicious_packages_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        if self.store_success:
            # Add packages that aren't already stored
            for package in packages:
                if package not in self.stored_malicious_packages:
                    self.stored_malicious_packages.append(package)
            return True
        else:
            return False
    
    async def health_check(self) -> bool:
        """Mock implementation of health_check."""
        self.health_check_call_count += 1
        
        if self.should_raise_error:
            raise Exception(self.error_message)
        
        return self.healthy

    async def get_scan_summary(self, limit: Optional[int] = None) -> List[dict]:
        """Return a lightweight summary of stored scan results (mock)."""
        if self.should_raise_error:
            raise Exception(self.error_message)
        results = self.stored_scan_results.copy()
        if limit is not None:
            results = results[:limit]
        return [
            {
                "scan_id": r.scan_id,
                "status": r.status.value if hasattr(r.status, 'value') else r.status,
                "packages_scanned": r.packages_scanned,
                "malicious_found": len(r.malicious_packages_found),
                "timestamp": r.timestamp.isoformat(),
            }
            for r in results
        ]


class TestStorageServiceInterface:
    """Test cases for StorageService interface."""
    
    @pytest.fixture
    def sample_scan_results(self):
        """Create sample scan results for testing."""
        return [
            ScanResult(
                scan_id="scan-001",
                timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                status=ScanStatus.SUCCESS,
                packages_scanned=100,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=30.5
            ),
            ScanResult(
                scan_id="scan-002",
                timestamp=datetime(2023, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
                status=ScanStatus.FAILED,
                packages_scanned=0,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=["Connection failed"],
                execution_duration_seconds=5.0
            ),
            ScanResult(
                scan_id="scan-003",
                timestamp=datetime(2023, 1, 3, 12, 0, 0, tzinfo=timezone.utc),
                status=ScanStatus.SUCCESS,
                packages_scanned=50,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=[],
                execution_duration_seconds=15.2
            )
        ]
    
    @pytest.fixture
    def sample_malicious_packages(self):
        """Create sample malicious packages for testing."""
        return [
            MaliciousPackage(
                name="malicious-pkg-1",
                version="1.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/malicious-pkg-1@1.0.0",
                advisory_id="OSV-2023-0001",
                summary="First malicious package",
                details="Contains backdoor",
                aliases=["CVE-2023-1234"],
                affected_versions=["1.0.0"],
                database_specific={"severity": "HIGH"},
                published_at=datetime(2023, 1, 1, 12, 0, 0),
                modified_at=datetime(2023, 1, 2, 12, 0, 0)
            ),
            MaliciousPackage(
                name="malicious-pkg-2",
                version="2.1.0",
                ecosystem="npm",
                package_url="pkg:npm/malicious-pkg-2@2.1.0",
                advisory_id="OSV-2023-0002",
                summary="Second malicious package",
                details="Contains crypto miner",
                aliases=["CVE-2023-5678"],
                affected_versions=["2.1.0"],
                database_specific={"severity": "CRITICAL"},
                published_at=datetime(2023, 2, 1, 12, 0, 0),
                modified_at=datetime(2023, 2, 2, 12, 0, 0)
            )
        ]
    
    @pytest.fixture
    def mock_storage_service(self):
        """Create a mock storage service."""
        return MockStorageService()
    
    def test_mock_storage_service_initialization(self):
        """Test mock storage service initialization."""
        service = MockStorageService()
        
        assert service.stored_scan_results == []
        assert service.stored_malicious_packages == []
        assert service.healthy is True
        assert service.store_scan_result_call_count == 0
        assert service.get_scan_results_call_count == 0
        assert service.should_raise_error is False
        assert service.store_success is True
    
    @pytest.mark.asyncio
    async def test_store_scan_result_success(self, mock_storage_service, sample_scan_results):
        """Test successful scan result storage."""
        result = await mock_storage_service.store_scan_result(sample_scan_results[0])
        
        assert result is True
        assert mock_storage_service.store_scan_result_call_count == 1
        assert len(mock_storage_service.stored_scan_results) == 1
        assert mock_storage_service.stored_scan_results[0] == sample_scan_results[0]
    
    @pytest.mark.asyncio
    async def test_store_scan_result_failure(self, mock_storage_service, sample_scan_results):
        """Test scan result storage failure."""
        mock_storage_service.store_success = False
        
        result = await mock_storage_service.store_scan_result(sample_scan_results[0])
        
        assert result is False
        assert mock_storage_service.store_scan_result_call_count == 1
        assert len(mock_storage_service.stored_scan_results) == 0
    
    @pytest.mark.asyncio
    async def test_store_scan_result_error(self, mock_storage_service, sample_scan_results):
        """Test scan result storage when error occurs."""
        mock_storage_service.should_raise_error = True
        mock_storage_service.error_message = "Storage connection failed"
        
        with pytest.raises(Exception, match="Storage connection failed"):
            await mock_storage_service.store_scan_result(sample_scan_results[0])
        
        assert mock_storage_service.store_scan_result_call_count == 1
        assert len(mock_storage_service.stored_scan_results) == 0
    
    @pytest.mark.asyncio
    async def test_store_multiple_scan_results(self, mock_storage_service, sample_scan_results):
        """Test storing multiple scan results."""
        for scan_result in sample_scan_results:
            result = await mock_storage_service.store_scan_result(scan_result)
            assert result is True
        
        assert mock_storage_service.store_scan_result_call_count == 3
        assert len(mock_storage_service.stored_scan_results) == 3
        
        # Verify all results were stored in order
        for i, stored_result in enumerate(mock_storage_service.stored_scan_results):
            assert stored_result.scan_id == sample_scan_results[i].scan_id
    
    @pytest.mark.asyncio
    async def test_get_scan_results_all(self, mock_storage_service, sample_scan_results):
        """Test retrieving all scan results."""
        # First store some results
        for scan_result in sample_scan_results:
            await mock_storage_service.store_scan_result(scan_result)
        
        # Retrieve all results
        results = await mock_storage_service.get_scan_results()
        
        assert mock_storage_service.get_scan_results_call_count == 1
        assert len(results) == 3
        assert results == sample_scan_results
    
    @pytest.mark.asyncio
    async def test_get_scan_results_with_limit(self, mock_storage_service, sample_scan_results):
        """Test retrieving scan results with limit."""
        # Store results
        for scan_result in sample_scan_results:
            await mock_storage_service.store_scan_result(scan_result)
        
        # Retrieve with limit
        results = await mock_storage_service.get_scan_results(limit=2)
        
        assert len(results) == 2
        assert results == sample_scan_results[:2]
    
    @pytest.mark.asyncio
    async def test_get_scan_results_by_scan_id(self, mock_storage_service, sample_scan_results):
        """Test retrieving scan results by specific scan ID."""
        # Store results
        for scan_result in sample_scan_results:
            await mock_storage_service.store_scan_result(scan_result)
        
        # Retrieve specific scan
        results = await mock_storage_service.get_scan_results(scan_id="scan-002")
        
        assert len(results) == 1
        assert results[0].scan_id == "scan-002"
        assert results[0].status == ScanStatus.FAILED
    
    @pytest.mark.asyncio
    async def test_get_scan_results_nonexistent_scan_id(self, mock_storage_service, sample_scan_results):
        """Test retrieving scan results with nonexistent scan ID."""
        # Store results
        for scan_result in sample_scan_results:
            await mock_storage_service.store_scan_result(scan_result)
        
        # Try to retrieve nonexistent scan
        results = await mock_storage_service.get_scan_results(scan_id="nonexistent")
        
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_get_scan_results_empty_storage(self, mock_storage_service):
        """Test retrieving scan results when storage is empty."""
        results = await mock_storage_service.get_scan_results()
        
        assert len(results) == 0
        assert mock_storage_service.get_scan_results_call_count == 1
    
    @pytest.mark.asyncio
    async def test_get_scan_results_error(self, mock_storage_service):
        """Test get_scan_results when error occurs."""
        mock_storage_service.should_raise_error = True
        mock_storage_service.error_message = "Retrieval failed"
        
        with pytest.raises(Exception, match="Retrieval failed"):
            await mock_storage_service.get_scan_results()
        
        assert mock_storage_service.get_scan_results_call_count == 1
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_success(self, mock_storage_service, sample_malicious_packages):
        """Test successful malicious packages storage."""
        result = await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        assert result is True
        assert mock_storage_service.store_malicious_packages_call_count == 1
        assert len(mock_storage_service.stored_malicious_packages) == 2
        assert mock_storage_service.stored_malicious_packages == sample_malicious_packages
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_duplicates(self, mock_storage_service, sample_malicious_packages):
        """Test storing malicious packages with duplicates."""
        # Store packages first time
        await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        # Store same packages again
        result = await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        assert result is True
        assert mock_storage_service.store_malicious_packages_call_count == 2
        assert len(mock_storage_service.stored_malicious_packages) == 2  # No duplicates
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_failure(self, mock_storage_service, sample_malicious_packages):
        """Test malicious packages storage failure."""
        mock_storage_service.store_success = False
        
        result = await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        assert result is False
        assert mock_storage_service.store_malicious_packages_call_count == 1
        assert len(mock_storage_service.stored_malicious_packages) == 0
    
    @pytest.mark.asyncio
    async def test_store_malicious_packages_error(self, mock_storage_service, sample_malicious_packages):
        """Test store_malicious_packages when error occurs."""
        mock_storage_service.should_raise_error = True
        mock_storage_service.error_message = "Package storage failed"
        
        with pytest.raises(Exception, match="Package storage failed"):
            await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        assert mock_storage_service.store_malicious_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_get_known_malicious_packages(self, mock_storage_service, sample_malicious_packages):
        """Test retrieving known malicious packages."""
        # Store packages first
        await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        # Retrieve packages
        packages = await mock_storage_service.get_known_malicious_packages()
        
        assert mock_storage_service.get_known_malicious_packages_call_count == 1
        assert len(packages) == 2
        assert packages == sample_malicious_packages
    
    @pytest.mark.asyncio
    async def test_get_known_malicious_packages_empty(self, mock_storage_service):
        """Test retrieving known malicious packages when storage is empty."""
        packages = await mock_storage_service.get_known_malicious_packages()
        
        assert len(packages) == 0
        assert mock_storage_service.get_known_malicious_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_get_known_malicious_packages_error(self, mock_storage_service):
        """Test get_known_malicious_packages when error occurs."""
        mock_storage_service.should_raise_error = True
        mock_storage_service.error_message = "Package retrieval failed"
        
        with pytest.raises(Exception, match="Package retrieval failed"):
            await mock_storage_service.get_known_malicious_packages()
        
        assert mock_storage_service.get_known_malicious_packages_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_storage_service):
        """Test health check when service is healthy."""
        result = await mock_storage_service.health_check()
        
        assert result is True
        assert mock_storage_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_storage_service):
        """Test health check when service is unhealthy."""
        mock_storage_service.healthy = False
        
        result = await mock_storage_service.health_check()
        
        assert result is False
        assert mock_storage_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_health_check_error(self, mock_storage_service):
        """Test health check when error occurs."""
        mock_storage_service.should_raise_error = True
        mock_storage_service.error_message = "Health check failed"
        
        with pytest.raises(Exception, match="Health check failed"):
            await mock_storage_service.health_check()
        
        assert mock_storage_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_interface_contract_compliance(self, mock_storage_service, sample_scan_results, sample_malicious_packages):
        """Test that mock implementation complies with interface contract."""
        # Verify it's an instance of the interface
        assert isinstance(mock_storage_service, StorageService)
        
        # Verify methods exist and are callable
        assert hasattr(mock_storage_service, 'store_scan_result')
        assert hasattr(mock_storage_service, 'get_scan_results')
        assert hasattr(mock_storage_service, 'get_known_malicious_packages')
        assert hasattr(mock_storage_service, 'store_malicious_packages')
        assert hasattr(mock_storage_service, 'health_check')
        
        # Test all methods return expected types
        store_result = await mock_storage_service.store_scan_result(sample_scan_results[0])
        assert isinstance(store_result, bool)
        
        scan_results = await mock_storage_service.get_scan_results()
        assert isinstance(scan_results, list)
        
        packages = await mock_storage_service.get_known_malicious_packages()
        assert isinstance(packages, list)
        
        store_packages_result = await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        assert isinstance(store_packages_result, bool)
        
        health_result = await mock_storage_service.health_check()
        assert isinstance(health_result, bool)
    
    def test_interface_is_abstract(self):
        """Test that StorageService interface cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class StorageService"):
            StorageService()  # pylint: disable=abstract-class-instantiated
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mock_storage_service, sample_scan_results, sample_malicious_packages):
        """Test concurrent storage operations."""
        import asyncio
        
        # Create multiple concurrent tasks
        tasks = [
            mock_storage_service.store_scan_result(sample_scan_results[0]),
            mock_storage_service.store_malicious_packages(sample_malicious_packages),
            mock_storage_service.get_scan_results(),
            mock_storage_service.health_check()
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify results
        assert len(results) == 4
        assert isinstance(results[0], bool)   # store_scan_result result
        assert isinstance(results[1], bool)   # store_malicious_packages result
        assert isinstance(results[2], list)   # get_scan_results result
        assert isinstance(results[3], bool)   # health_check result
        
        # Verify call counters
        assert mock_storage_service.store_scan_result_call_count == 1
        assert mock_storage_service.store_malicious_packages_call_count == 1
        assert mock_storage_service.get_scan_results_call_count == 1
        assert mock_storage_service.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_full_storage_lifecycle(self, mock_storage_service, sample_scan_results, sample_malicious_packages):
        """Test a complete storage lifecycle workflow."""
        # 1. Initially empty
        scan_results = await mock_storage_service.get_scan_results()
        packages = await mock_storage_service.get_known_malicious_packages()
        assert len(scan_results) == 0
        assert len(packages) == 0
        
        # 2. Store some data
        for scan_result in sample_scan_results:
            result = await mock_storage_service.store_scan_result(scan_result)
            assert result is True
        
        result = await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        assert result is True
        
        # 3. Verify data was stored
        scan_results = await mock_storage_service.get_scan_results()
        packages = await mock_storage_service.get_known_malicious_packages()
        assert len(scan_results) == 3
        assert len(packages) == 2
        
        # 4. Test filtering and limits
        limited_results = await mock_storage_service.get_scan_results(limit=1)
        assert len(limited_results) == 1
        
        specific_result = await mock_storage_service.get_scan_results(scan_id="scan-002")
        assert len(specific_result) == 1
        assert specific_result[0].scan_id == "scan-002"
        
        # 5. Health check should still be healthy
        health = await mock_storage_service.health_check()
        assert health is True
    
    @pytest.mark.asyncio
    async def test_error_handling_scenarios(self, mock_storage_service, sample_scan_results, sample_malicious_packages):
        """Test various error handling scenarios."""
        # Test errors during different operations
        mock_storage_service.should_raise_error = True
        
        # Store scan result error
        mock_storage_service.error_message = "Store scan error"
        with pytest.raises(Exception, match="Store scan error"):
            await mock_storage_service.store_scan_result(sample_scan_results[0])
        
        # Get scan results error
        mock_storage_service.error_message = "Get scan error"
        with pytest.raises(Exception, match="Get scan error"):
            await mock_storage_service.get_scan_results()
        
        # Store packages error
        mock_storage_service.error_message = "Store packages error"
        with pytest.raises(Exception, match="Store packages error"):
            await mock_storage_service.store_malicious_packages(sample_malicious_packages)
        
        # Get packages error
        mock_storage_service.error_message = "Get packages error"
        with pytest.raises(Exception, match="Get packages error"):
            await mock_storage_service.get_known_malicious_packages()
        
        # Health check error
        mock_storage_service.error_message = "Health error"
        with pytest.raises(Exception, match="Health error"):
            await mock_storage_service.health_check()
    
    @pytest.mark.asyncio
    async def test_large_data_operations(self, mock_storage_service):
        """Test operations with large datasets."""
        # Create large dataset
        large_scan_results = []
        for i in range(100):
            large_scan_results.append(
                ScanResult(
                    scan_id=f"large-scan-{i:03d}",
                    timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                    status=ScanStatus.SUCCESS,
                    packages_scanned=i * 10,
                    malicious_packages_found=[],
                    packages_blocked=[],
                    malicious_packages_list=[],
                    errors=[],
                    execution_duration_seconds=float(i)
                )
            )
        
        # Store all results
        for scan_result in large_scan_results:
            result = await mock_storage_service.store_scan_result(scan_result)
            assert result is True
        
        # Retrieve all
        all_results = await mock_storage_service.get_scan_results()
        assert len(all_results) == 100
        
        # Test large limit
        limited_results = await mock_storage_service.get_scan_results(limit=50)
        assert len(limited_results) == 50
        
        # Verify call counts
        assert mock_storage_service.store_scan_result_call_count == 100
        assert mock_storage_service.get_scan_results_call_count == 2