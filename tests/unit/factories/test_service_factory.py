"""Tests for service factory."""

from unittest.mock import MagicMock, patch

import pytest

from src.config import Config
from src.factories.service_factory import ServiceFactory, ServiceFactoryError


class TestServiceFactory:
    """Test suite for ServiceFactory."""

    @pytest.fixture
    def basic_config(self):
        """Create a basic configuration for testing."""
        config_data = {
            "packages_feed": {
                "type": "osv",
                "enabled": True,
                "config": {
                    "bucket_name": "test-bucket",
                    "timeout_seconds": 30,
                    "max_retries": 3,
                    "retry_delay": 1.0,
                },
            },
            "packages_registry": {
                "type": "jfrog",
                "enabled": True,
                "config": {"timeout_seconds": 30, "max_retries": 3, "retry_delay": 1.0},
            },
            "notification_service": {
                "type": "composite",
                "enabled": True,
                "config": {},
            },
            "storage_service": {
                "type": "file",
                "config": {
                    "data_directory": "test_data",
                    "scan_results_file": "test_scan_results.jsonl",
                    "malicious_packages_file": "test_malicious_packages.json",
                    "max_scan_results": 1000,
                    "backup_enabled": True,
                },
            },
            "jfrog_base_url": "https://test.jfrog.io",
            "jfrog_username": "test_user",
            "jfrog_password": "test_pass",
            "jfrog_api_key": "test_key",
        }
        return Config(**config_data)

    @pytest.fixture
    def service_factory(self, basic_config):
        """Create service factory instance."""
        return ServiceFactory(basic_config)

    def test_init(self, basic_config):
        """Test service factory initialization."""
        factory = ServiceFactory(basic_config)
        assert factory.config == basic_config

    @patch("src.factories.service_factory.OSVFeed")
    def test_create_packages_feed_osv_success(self, mock_osv_feed, service_factory):
        """Test successful creation of OSV packages feed."""
        mock_instance = MagicMock()
        mock_osv_feed.return_value = mock_instance

        result = service_factory.create_packages_feed()

        assert result == mock_instance
        mock_osv_feed.assert_called_once_with(
            bucket_name="test-bucket",
            timeout_seconds=30,
            max_retries=3,
            retry_delay=1.0,
        )

    def test_create_packages_feed_unknown_type(self, service_factory):
        """Test creation of packages feed with unknown type."""
        service_factory.config.packages_feed.type = "unknown"

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_packages_feed()

        assert "Unknown packages feed type: unknown" in str(exc_info.value)

    @patch("src.factories.service_factory.OSVFeed")
    def test_create_packages_feed_creation_error(self, mock_osv_feed, service_factory):
        """Test packages feed creation with provider instantiation error."""
        mock_osv_feed.side_effect = Exception("Provider creation failed")

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_packages_feed()

        assert "Failed to create packages feed: Provider creation failed" in str(
            exc_info.value
        )

    @patch("src.factories.service_factory.JFrogRegistry")
    def test_create_packages_registry_jfrog_success(
        self, mock_jfrog_registry, service_factory
    ):
        """Test successful creation of JFrog packages registry."""
        mock_instance = MagicMock()
        mock_jfrog_registry.return_value = mock_instance

        result = service_factory.create_packages_registry()

        assert result == mock_instance
        mock_jfrog_registry.assert_called_once_with(
            base_url="https://test.jfrog.io",
            username="test_user",
            password="test_pass",
            api_key="test_key",
            timeout_seconds=30,
            max_retries=3,
            retry_delay=1.0,
            repository_overrides={},
            cache_ttl_seconds=3600,
        )

    def test_create_packages_registry_disabled(self, service_factory):
        """Test creation of packages registry when disabled."""
        service_factory.config.packages_registry.enabled = False

        with patch.object(service_factory, "_create_null_registry") as mock_null:
            mock_null_instance = MagicMock()
            mock_null.return_value = mock_null_instance

            result = service_factory.create_packages_registry()

            assert result == mock_null_instance
            mock_null.assert_called_once()

    def test_create_packages_registry_missing_base_url(self, service_factory):
        """Test packages registry creation with missing base URL."""
        service_factory.config.jfrog_base_url = None

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_packages_registry()

        assert "JFrog base URL not configured" in str(exc_info.value)

    def test_create_packages_registry_unknown_type(self, service_factory):
        """Test creation of packages registry with unknown type."""
        service_factory.config.packages_registry.type = "unknown"

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_packages_registry()

        assert "Unknown packages registry type: unknown" in str(exc_info.value)

    @patch("src.factories.service_factory.JFrogRegistry")
    def test_create_packages_registry_creation_error(
        self, mock_jfrog_registry, service_factory
    ):
        """Test packages registry creation with provider instantiation error."""
        mock_jfrog_registry.side_effect = Exception("Registry creation failed")

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_packages_registry()

        assert "Failed to create packages registry: Registry creation failed" in str(
            exc_info.value
        )

    def test_create_notification_service_disabled(self, service_factory):
        """Test creation of notification service when disabled."""
        service_factory.config.notification_service.enabled = False

        with patch.object(service_factory, "_create_null_notifier") as mock_null:
            mock_null_instance = MagicMock()
            mock_null.return_value = mock_null_instance

            result = service_factory.create_notification_service()

            assert result == mock_null_instance
            mock_null.assert_called_once()

    def test_create_notification_service_null_type(self, service_factory):
        """Test creation of null notification service."""
        service_factory.config.notification_service.type = "null"

        with patch.object(service_factory, "_create_null_notifier") as mock_null:
            mock_null_instance = MagicMock()
            mock_null.return_value = mock_null_instance

            result = service_factory.create_notification_service()

            assert result == mock_null_instance
            mock_null.assert_called_once()

    def test_create_notification_service_composite_type(self, service_factory):
        """Test creation of composite notification service (fallback to null)."""
        service_factory.config.notification_service.type = "composite"

        with patch.object(service_factory, "_create_null_notifier") as mock_null:
            mock_null_instance = MagicMock()
            mock_null.return_value = mock_null_instance

            result = service_factory.create_notification_service()

            assert result == mock_null_instance
            mock_null.assert_called_once()

    def test_create_notification_service_unknown_type(self, service_factory):
        """Test creation of notification service with unknown type."""
        service_factory.config.notification_service.type = "unknown"

        with patch.object(service_factory, "_create_null_notifier") as mock_null:
            mock_null_instance = MagicMock()
            mock_null.return_value = mock_null_instance

            result = service_factory.create_notification_service()

            assert result == mock_null_instance
            mock_null.assert_called_once()

    @patch("src.factories.service_factory.FileStorage")
    def test_create_storage_service_file_success(
        self, mock_file_storage, service_factory
    ):
        """Test successful creation of file storage service."""
        mock_instance = MagicMock()
        mock_file_storage.return_value = mock_instance

        result = service_factory.create_storage_service()

        assert result == mock_instance
        mock_file_storage.assert_called_once_with(data_directory="test_data")

    @patch("src.factories.service_factory.DatabaseStorage")
    def test_create_storage_service_database_success(
        self, mock_db_storage, service_factory
    ):
        """Test successful creation of database storage service."""
        service_factory.config.storage_service.type = "database"
        service_factory.config.storage_service.config = {
            "database_path": "test.db",
            "connection_timeout": 30.0,
            "max_connections": 10,
        }

        mock_instance = MagicMock()
        mock_db_storage.return_value = mock_instance

        result = service_factory.create_storage_service()

        assert result == mock_instance
        mock_db_storage.assert_called_once_with(
            database_path="test.db",
            connection_timeout=30.0,
            max_connections=10,
            in_memory=False,
        )

    @patch("src.factories.service_factory.DatabaseStorage")
    def test_create_storage_service_sqlite_success(
        self, mock_db_storage, service_factory
    ):
        """Test successful creation of sqlite storage service."""
        service_factory.config.storage_service.type = "sqlite"
        service_factory.config.storage_service.config = {
            "database_path": "test.db",
            "connection_timeout": 30.0,
            "max_connections": 10,
        }

        mock_instance = MagicMock()
        mock_db_storage.return_value = mock_instance

        result = service_factory.create_storage_service()

        assert result == mock_instance
        mock_db_storage.assert_called_once_with(
            database_path="test.db",
            connection_timeout=30.0,
            max_connections=10,
            in_memory=False,
        )

    def test_create_storage_service_unknown_type(self, service_factory):
        """Test creation of storage service with unknown type."""
        service_factory.config.storage_service.type = "unknown"

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_storage_service()

        assert "Unknown storage service type: unknown" in str(exc_info.value)

    @patch("src.factories.service_factory.FileStorage")
    def test_create_storage_service_creation_error(
        self, mock_file_storage, service_factory
    ):
        """Test storage service creation with provider instantiation error."""
        mock_file_storage.side_effect = Exception("Storage creation failed")

        with pytest.raises(ServiceFactoryError) as exc_info:
            service_factory.create_storage_service()

        assert "Failed to create storage service: Storage creation failed" in str(
            exc_info.value
        )

    def test_create_null_notifier(self, service_factory):
        """Test creation of null notifier."""
        # Instead of comparing object instances, we'll check the type
        result = service_factory._create_null_notifier()

        # Check that the result is an instance of NullNotifier
        from src.providers.notifications.null_notifier import NullNotifier

        assert isinstance(result, NullNotifier)

    def test_create_null_registry(self, service_factory):
        """Test creation of null registry."""
        # Instead of comparing object instances, we'll check the type
        result = service_factory._create_null_registry()

        # Check that the result is an instance of NullRegistry
        from src.providers.registries.null_registry import NullRegistry

        assert isinstance(result, NullRegistry)

    def test_create_packages_feed_with_default_config(self, service_factory):
        """Test packages feed creation with minimal config (using defaults)."""
        service_factory.config.packages_feed.config = {}

        with patch("src.factories.service_factory.OSVFeed") as mock_osv_feed:
            mock_instance = MagicMock()
            mock_osv_feed.return_value = mock_instance

            result = service_factory.create_packages_feed()

            assert result == mock_instance
            mock_osv_feed.assert_called_once_with(
                bucket_name="osv-vulnerabilities",
                timeout_seconds=30,
                max_retries=3,
                retry_delay=1.0,
            )

    def test_create_storage_service_with_default_config(self, service_factory):
        """Test storage service creation with minimal config (using defaults)."""
        service_factory.config.storage_service.config = {}

        with patch("src.factories.service_factory.FileStorage") as mock_file_storage:
            mock_instance = MagicMock()
            mock_file_storage.return_value = mock_instance

            result = service_factory.create_storage_service()

            assert result == mock_instance
            mock_file_storage.assert_called_once_with(data_directory="scan_results")
