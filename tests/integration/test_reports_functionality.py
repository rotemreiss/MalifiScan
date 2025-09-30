"""Integration tests for reports functionality with different storage providers."""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.config import Config, ConfigLoader
from src.core.entities import ScanResult, ScanStatus
from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.factories import ServiceFactory
from src.providers.storage import DatabaseStorage, FileStorage, MemoryStorage


class TestReportsIntegration:
    """Integration tests for reports functionality."""

    @pytest.fixture
    def base_config(self):
        """Base configuration for testing."""
        return {
            "environment": "test",
            "debug": True,
            "packages_feed": {
                "type": "osv",
                "enabled": True,
                "config": {"timeout_seconds": 30, "max_retries": 3, "retry_delay": 1.0},
            },
            "packages_registry": {
                "type": "jfrog",
                "enabled": False,  # Disabled for testing
                "config": {"timeout_seconds": 30, "max_retries": 3, "retry_delay": 1.0},
            },
            "notification_service": {
                "type": "null",
                "enabled": False,
                "channels": [],
                "config": {"timeout_seconds": 30, "max_retries": 3, "retry_delay": 1.0},
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file_path": None,
                "max_file_size_mb": 10,
                "backup_count": 5,
            },
        }

    @pytest.fixture
    def memory_config(self, base_config):
        """Configuration with memory storage."""
        config = base_config.copy()
        config["storage_service"] = {
            "type": "memory",
            "enabled": True,
            "config": {"max_scan_results": 100, "clear_on_init": True},
        }
        return Config(**config)

    @pytest.fixture
    def file_config(self, base_config):
        """Configuration with file storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = base_config.copy()
            config["storage_service"] = {
                "type": "file",
                "enabled": True,
                "config": {"data_directory": temp_dir},
            }
            yield Config(**config)

    @pytest.fixture
    def sqlite_config(self, base_config):
        """Configuration with SQLite storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = base_config.copy()
            config["storage_service"] = {
                "type": "sqlite",
                "enabled": True,
                "config": {
                    "database_path": os.path.join(temp_dir, "test_security_scanner.db"),
                    "connection_timeout": 30.0,
                    "max_connections": 10,
                },
            }
            yield Config(**config)

    async def test_memory_storage_integration(self, memory_config):
        """Test that memory storage works correctly in integration."""
        # Create service factory and storage service
        factory = ServiceFactory(memory_config)
        storage_service = factory.create_storage_service()

        assert isinstance(storage_service, MemoryStorage)

        # Test health check
        assert await storage_service.health_check() is True

        # Test that storage starts empty
        scan_results = await storage_service.get_scan_results()
        assert len(scan_results) == 0

        # Test storing a scan result
        scan_result = ScanResult(
            scan_id="test-integration-001",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=5,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=2.5,
        )

        result = await storage_service.store_scan_result(scan_result)
        assert result is True

        # Test retrieving the scan result
        stored_results = await storage_service.get_scan_results()
        assert len(stored_results) == 1
        assert stored_results[0].scan_id == "test-integration-001"

        # Test storage statistics
        stats = storage_service.get_stats()
        assert stats["type"] == "memory"
        assert stats["scan_results_count"] == 1

    async def test_file_storage_integration(self, file_config):
        """Test that file storage works correctly in integration."""
        # Create service factory and storage service
        factory = ServiceFactory(file_config)
        storage_service = factory.create_storage_service()

        assert isinstance(storage_service, FileStorage)

        # Test health check
        assert await storage_service.health_check() is True

        # Test storing a scan result
        scan_result = ScanResult(
            scan_id="test-file-integration-001",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=3,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=1.5,
        )

        result = await storage_service.store_scan_result(scan_result)
        assert result is True

        # Test retrieving the scan result
        stored_results = await storage_service.get_scan_results()
        assert len(stored_results) == 1
        assert stored_results[0].scan_id == "test-file-integration-001"

        # Verify files were created
        data_dir = Path(file_config.storage_service.config["data_directory"])
        expected_file = data_dir / f"{scan_result.scan_id}.json"
        assert expected_file.exists()

    async def test_sqlite_storage_integration(self, sqlite_config):
        """Test that SQLite storage works correctly in integration."""
        # Create service factory and storage service
        factory = ServiceFactory(sqlite_config)
        storage_service = factory.create_storage_service()

        assert isinstance(storage_service, DatabaseStorage)

        # Test health check
        assert await storage_service.health_check() is True

        # Test storing a scan result
        scan_result = ScanResult(
            scan_id="test-sqlite-integration-001",
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=7,
            malicious_packages_found=[],
            packages_blocked=[],
            malicious_packages_list=[],
            errors=[],
            execution_duration_seconds=3.2,
        )

        result = await storage_service.store_scan_result(scan_result)
        assert result is True

        # Test retrieving the scan result
        stored_results = await storage_service.get_scan_results()
        assert len(stored_results) == 1
        assert stored_results[0].scan_id == "test-sqlite-integration-001"

        # Verify database file was created
        db_path = Path(sqlite_config.storage_service.config["database_path"])
        assert db_path.exists()


class TestReportSavingLogic:
    """Test the automatic report saving logic in security analysis."""

    @pytest.fixture
    async def mock_security_analysis_usecase(self):
        """Create a mock security analysis use case for testing."""
        from unittest.mock import AsyncMock

        # Create mock services
        mock_feed = AsyncMock()
        mock_registry = AsyncMock()
        mock_storage = AsyncMock()

        # Configure mock feed to return empty list
        mock_feed.fetch_malicious_packages.return_value = []

        # Configure mock registry health check
        mock_registry.health_check.return_value = True
        mock_registry.close.return_value = None

        # Configure mock storage
        mock_storage.store_scan_result.return_value = True

        # Create use case
        use_case = SecurityAnalysisUseCase(
            packages_feed=mock_feed,
            registry_service=mock_registry,
            storage_service=mock_storage,
        )

        return use_case, mock_storage

    async def test_crossref_analysis_saves_report_by_default(
        self, mock_security_analysis_usecase
    ):
        """Test that crossref analysis saves reports by default."""
        use_case, mock_storage = mock_security_analysis_usecase

        # Run analysis with default save_report=True
        result = await use_case.crossref_analysis(hours=6, ecosystem="npm", limit=10)

        # Verify report was attempted to be saved
        assert result["success"] is True
        assert result["report_saved"] is True
        assert mock_storage.store_scan_result.called

    async def test_crossref_analysis_skips_report_when_disabled(
        self, mock_security_analysis_usecase
    ):
        """Test that crossref analysis skips saving when save_report=False."""
        use_case, mock_storage = mock_security_analysis_usecase

        # Run analysis with save_report=False
        result = await use_case.crossref_analysis(
            hours=6, ecosystem="npm", limit=10, save_report=False
        )

        # Verify report was not saved
        assert result["success"] is True
        assert result["report_saved"] is False
        assert not mock_storage.store_scan_result.called

    async def test_crossref_analysis_handles_storage_failure(
        self, mock_security_analysis_usecase
    ):
        """Test that crossref analysis handles storage failures gracefully."""
        use_case, mock_storage = mock_security_analysis_usecase

        # Configure storage to fail
        mock_storage.store_scan_result.side_effect = Exception("Storage failed")

        # Run analysis
        result = await use_case.crossref_analysis(
            hours=6, ecosystem="npm", limit=10, save_report=True
        )

        # Verify analysis still succeeds but report saving failed
        assert result["success"] is True
        assert result["report_saved"] is False
        assert "Failed to save scan result" in str(result["errors"])

    async def test_crossref_analysis_without_storage_service(self):
        """Test crossref analysis when no storage service is provided."""
        from unittest.mock import AsyncMock

        # Create mock services without storage
        mock_feed = AsyncMock()
        mock_registry = AsyncMock()

        mock_feed.fetch_malicious_packages.return_value = []
        mock_registry.health_check.return_value = True
        mock_registry.close.return_value = None

        # Create use case without storage service
        use_case = SecurityAnalysisUseCase(
            packages_feed=mock_feed,
            registry_service=mock_registry,
            storage_service=None,
        )

        # Run analysis
        result = await use_case.crossref_analysis(
            hours=6, ecosystem="npm", limit=10, save_report=True
        )

        # Verify analysis succeeds but no report is saved
        assert result["success"] is True
        assert result["report_saved"] is False


class TestDefaultStorageConfiguration:
    """Test that memory storage is correctly configured as default."""

    def test_default_config_uses_memory_storage(self):
        """Test that the default configuration uses memory storage."""
        # Read the actual config file
        config_path = Path(__file__).parent.parent.parent.parent / "config.yaml"

        if config_path.exists():
            config_loader = ConfigLoader(str(config_path))
            config = config_loader.load()

            # Verify memory storage is the default
            assert config.storage_service.type == "memory"
            assert config.storage_service.enabled is True

    def test_memory_storage_factory_creation(self):
        """Test that service factory correctly creates memory storage."""
        config_dict = {
            "environment": "test",
            "debug": True,
            "storage_service": {
                "type": "memory",
                "enabled": True,
                "config": {"max_scan_results": 500, "clear_on_init": False},
            },
            "packages_feed": {"type": "osv", "enabled": True, "config": {}},
            "packages_registry": {"type": "jfrog", "enabled": False, "config": {}},
            "notification_service": {"type": "null", "enabled": False, "config": {}},
            "logging": {
                "level": "INFO",
                "format": "test",
                "file_path": None,
                "max_file_size_mb": 10,
                "backup_count": 5,
            },
        }

        config = Config(**config_dict)
        factory = ServiceFactory(config)
        storage_service = factory.create_storage_service()

        assert isinstance(storage_service, MemoryStorage)
        assert storage_service.max_scan_results == 500
