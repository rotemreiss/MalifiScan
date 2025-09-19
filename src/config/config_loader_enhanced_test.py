"""Enhanced tests for config_loader to improve coverage."""

import pytest
import tempfile
import os
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open

from src.config.config_loader import (
    ConfigLoader, Config, ProviderConfig, FeedConfig, RegistryConfig, 
    NotificationConfig, StorageConfig, LoggingConfig
)
from src.config.exceptions import ConfigError, ConfigValidationError, ConfigFileNotFoundError


class TestConfigLoaderEnhanced:
    """Enhanced tests for ConfigLoader to improve coverage."""

    def test_init_with_all_parameters(self):
        """Test ConfigLoader initialization with all parameters."""
        loader = ConfigLoader(
            config_file="custom_config.yaml",
            env_file="custom.env",
            load_env_file=False,
            use_env_vars=False
        )
        
        assert loader.config_file == "custom_config.yaml"
        assert loader.env_file == "custom.env"
        assert loader.load_env_file is False
        assert loader.use_env_vars is False

    def test_init_with_defaults(self):
        """Test ConfigLoader initialization with default parameters."""
        loader = ConfigLoader()
        
        assert loader.config_file == "config.yaml"
        assert loader.env_file == ".env"
        assert loader.load_env_file is True
        assert loader.use_env_vars is True

    def test_load_with_invalid_yaml(self):
        """Test loading configuration with invalid YAML."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("invalid: yaml: content: [")
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            
            with pytest.raises(ConfigError, match="Failed to load configuration"):
                loader.load()

    def test_load_with_yaml_error_specific(self):
        """Test loading configuration with YAML syntax error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            environment: test
            invalid_yaml:
              - item1
             - item2  # Invalid indentation
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            
            with pytest.raises(ConfigError, match="Failed to load configuration"):
                loader.load()

    def test_load_with_file_read_error(self):
        """Test loading configuration when file can't be read."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: test")
            
            # Make file unreadable
            config_file.chmod(0o000)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            
            try:
                with pytest.raises(ConfigError, match="Failed to load configuration"):
                    loader.load()
            finally:
                # Restore permissions for cleanup
                config_file.chmod(0o644)

    def test_load_empty_yaml_file(self):
        """Test loading an empty YAML file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("")  # Empty file
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            # Should load with defaults
            assert config.environment == "development"
            assert config.debug is False

    def test_load_yaml_file_with_null_content(self):
        """Test loading YAML file that returns None when parsed."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("# Only comments\n")  # Results in None when parsed
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            # Should load with defaults
            assert config.environment == "development"

    def test_override_with_env_nested_config(self):
        """Test environment variable override for nested configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            environment: development
            logging:
              level: INFO
              file_path: null
            """)
            
            with patch.dict(os.environ, {
                'LOG_LEVEL': 'DEBUG',
                'LOG_FILE_PATH': '/var/log/app.log'
            }):
                loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=True)
                config = loader.load()
                
                assert config.logging.level == "DEBUG"
                assert config.logging.file_path == "/var/log/app.log"

    def test_override_with_env_creates_nested_dict(self):
        """Test environment variable override creates nested dictionary when missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: development")  # No logging section
            
            with patch.dict(os.environ, {'LOG_LEVEL': 'ERROR'}):
                loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=True)
                config = loader.load()
                
                assert config.logging.level == "ERROR"

    def test_convert_env_value_boolean_true(self):
        """Test conversion of boolean environment values."""
        loader = ConfigLoader()
        
        assert loader._convert_env_value("true", "debug") is True
        assert loader._convert_env_value("True", "debug") is True
        assert loader._convert_env_value("TRUE", "debug") is True
        assert loader._convert_env_value("false", "debug") is False
        assert loader._convert_env_value("False", "debug") is False
        assert loader._convert_env_value("FALSE", "debug") is False

    def test_convert_env_value_integer(self):
        """Test conversion of integer environment values."""
        loader = ConfigLoader()
        
        assert loader._convert_env_value("5432", "email_smtp_port") == 5432
        assert loader._convert_env_value("24", "interval_hours") == 24
        assert loader._convert_env_value("100", "max_file_size_mb") == 100
        assert loader._convert_env_value("10", "backup_count") == 10

    def test_convert_env_value_invalid_integer(self):
        """Test conversion of invalid integer environment values."""
        loader = ConfigLoader()
        
        # Should return string if can't convert to int
        assert loader._convert_env_value("not_a_number", "email_smtp_port") == "not_a_number"

    def test_convert_env_value_list(self):
        """Test conversion of list environment values."""
        loader = ConfigLoader()
        
        result = loader._convert_env_value("email1@example.com,email2@example.com", "email_to_addresses")
        assert result == ["email1@example.com", "email2@example.com"]
        
        # Test with spaces
        result = loader._convert_env_value("email1@example.com, email2@example.com ", "email_to_addresses")
        assert result == ["email1@example.com", "email2@example.com"]
        
        # Test with empty items
        result = loader._convert_env_value("email1@example.com,,email2@example.com", "email_to_addresses")
        assert result == ["email1@example.com", "email2@example.com"]

    def test_convert_env_value_string(self):
        """Test conversion of string environment values."""
        loader = ConfigLoader()
        
        assert loader._convert_env_value("production", "environment") == "production"
        assert loader._convert_env_value("https://api.example.com", "api_url") == "https://api.example.com"

    def test_validate_config_jfrog_enabled_missing_base_url(self):
        """Test validation failure when JFrog is enabled but base URL is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            packages_registry:
              type: jfrog
              enabled: true
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            
            with pytest.raises(ConfigError, match="JFrog base URL is required"):
                loader.load()

    def test_validate_config_jfrog_enabled_missing_credentials(self):
        """Test validation failure when JFrog is enabled but credentials are missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            packages_registry:
              type: jfrog
              enabled: true
            jfrog_base_url: "https://my-jfrog.example.com"
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            
            with pytest.raises(ConfigError, match="JFrog API key or username/password is required"):
                loader.load()

    def test_validate_config_jfrog_with_api_key(self):
        """Test validation success when JFrog is configured with API key."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            packages_registry:
              type: jfrog
              enabled: true
            jfrog_base_url: "https://my-jfrog.example.com"
            jfrog_api_key: "api_key_123"
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            assert config.packages_registry.enabled is True
            assert config.jfrog_base_url == "https://my-jfrog.example.com"
            assert config.jfrog_api_key == "api_key_123"

    def test_validate_config_jfrog_with_username_password(self):
        """Test validation success when JFrog is configured with username/password."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            packages_registry:
              type: jfrog
              enabled: true
            jfrog_base_url: "https://my-jfrog.example.com"
            jfrog_username: "user123"
            jfrog_password: "pass123"
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            assert config.packages_registry.enabled is True
            assert config.jfrog_username == "user123"
            assert config.jfrog_password == "pass123"

    def test_validate_config_jfrog_different_type(self):
        """Test validation when JFrog registry has different type."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
            packages_registry:
              type: artifactory
              enabled: true
            """)
            
            loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            # Should not trigger JFrog validation since type is not "jfrog"
            assert config.packages_registry.enabled is True
            assert config.packages_registry.type == "artifactory"

    def test_load_with_env_file_that_doesnt_exist(self):
        """Test loading when .env file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: test")
            
            nonexistent_env = Path(temp_dir) / "nonexistent.env"
            
            loader = ConfigLoader(str(config_file), str(nonexistent_env), load_env_file=True)
            config = loader.load()
            
            # Should load successfully without the env file
            assert config.environment == "test"

    def test_all_env_mappings(self):
        """Test all environment variable mappings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: development")
            
            env_vars = {
                'ENVIRONMENT': 'production',
                'DEBUG': 'true',
                'OSV_API_BASE_URL': 'https://custom-osv.example.com',
                'JFROG_BASE_URL': 'https://custom-jfrog.example.com',
                'JFROG_USERNAME': 'test_user',
                'JFROG_PASSWORD': 'test_pass',
                'JFROG_API_KEY': 'test_key',
                'LOG_LEVEL': 'WARNING',
                'LOG_FILE_PATH': '/tmp/app.log'
            }
            
            with patch.dict(os.environ, env_vars):
                loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=True)
                config = loader.load()
                
                assert config.environment == "production"
                assert config.debug is True
                assert config.osv_api_base_url == "https://custom-osv.example.com"
                assert config.jfrog_base_url == "https://custom-jfrog.example.com"
                assert config.jfrog_username == "test_user"
                assert config.jfrog_password == "test_pass"
                assert config.jfrog_api_key == "test_key"
                assert config.logging.level == "WARNING"
                assert config.logging.file_path == "/tmp/app.log"

    def test_load_env_file_when_disabled(self):
        """Test that .env file is not loaded when load_env_file is False."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: development")
            
            env_file = Path(temp_dir) / ".env"
            env_file.write_text("ENVIRONMENT=from_env_file")
            
            # Don't load env file, but do use env vars
            with patch.dict(os.environ, {'ENVIRONMENT': 'from_env_var'}):
                loader = ConfigLoader(str(config_file), str(env_file), load_env_file=False, use_env_vars=True)
                config = loader.load()
                
                # Should get value from env var, not env file
                assert config.environment == "from_env_var"

    def test_load_env_vars_when_disabled(self):
        """Test that environment variables are not used when use_env_vars is False."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("environment: from_yaml")
            
            with patch.dict(os.environ, {'ENVIRONMENT': 'from_env_var'}):
                loader = ConfigLoader(str(config_file), load_env_file=False, use_env_vars=False)
                config = loader.load()
                
                # Should get value from YAML, not env var
                assert config.environment == "from_yaml"

    def test_generic_exception_during_load(self):
        """Test generic exception handling during load process."""
        loader = ConfigLoader()
        
        # Mock the load method to raise a generic exception
        with patch.object(loader, '_load_yaml_config', side_effect=RuntimeError("Generic error")):
            with pytest.raises(ConfigError, match="Failed to load configuration: Generic error"):
                loader.load()


class TestConfigModels:
    """Test configuration model classes."""

    def test_provider_config_defaults(self):
        """Test ProviderConfig default values."""
        config = ProviderConfig(type="test")
        
        assert config.type == "test"
        assert config.enabled is True
        assert config.config == {}

    def test_provider_config_custom_values(self):
        """Test ProviderConfig with custom values."""
        config = ProviderConfig(
            type="custom",
            enabled=False,
            config={"key": "value"}
        )
        
        assert config.type == "custom"
        assert config.enabled is False
        assert config.config == {"key": "value"}

    def test_feed_config_defaults(self):
        """Test FeedConfig default values."""
        config = FeedConfig()
        
        assert config.type == "osv"
        assert config.enabled is True
        assert config.config == {}

    def test_registry_config_defaults(self):
        """Test RegistryConfig default values."""
        config = RegistryConfig()
        
        assert config.type == "jfrog"
        assert config.enabled is False  # Disabled by default
        assert config.config == {}

    def test_notification_config_defaults(self):
        """Test NotificationConfig default values."""
        config = NotificationConfig()
        
        assert config.type == "null"
        assert config.enabled is False  # Disabled by default
        assert config.channels == []

    def test_notification_config_custom_channels(self):
        """Test NotificationConfig with custom channels."""
        config = NotificationConfig(channels=["email", "slack"])
        
        assert config.channels == ["email", "slack"]

    def test_storage_config_defaults(self):
        """Test StorageConfig default values."""
        config = StorageConfig()
        
        assert config.type == "file"
        assert config.enabled is True
        assert config.config == {}

    def test_logging_config_defaults(self):
        """Test LoggingConfig default values."""
        config = LoggingConfig()
        
        assert config.level == "INFO"
        assert config.format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        assert config.file_path is None
        assert config.max_file_size_mb == 10
        assert config.backup_count == 5

    def test_logging_config_custom_values(self):
        """Test LoggingConfig with custom values."""
        config = LoggingConfig(
            level="DEBUG",
            format="%(levelname)s: %(message)s",
            file_path="/var/log/app.log",
            max_file_size_mb=50,
            backup_count=10
        )
        
        assert config.level == "DEBUG"
        assert config.format == "%(levelname)s: %(message)s"
        assert config.file_path == "/var/log/app.log"
        assert config.max_file_size_mb == 50
        assert config.backup_count == 10

    def test_config_defaults(self):
        """Test Config default values."""
        config = Config()
        
        assert config.environment == "development"
        assert config.debug is False
        assert isinstance(config.packages_feed, FeedConfig)
        assert isinstance(config.packages_registry, RegistryConfig)
        assert isinstance(config.notification_service, NotificationConfig)
        assert isinstance(config.storage_service, StorageConfig)
        assert isinstance(config.logging, LoggingConfig)
        assert config.osv_api_base_url == "https://osv-vulnerabilities.storage.googleapis.com"
        assert config.jfrog_base_url is None
        assert config.jfrog_username is None
        assert config.jfrog_password is None
        assert config.jfrog_api_key is None

    def test_config_custom_nested_values(self):
        """Test Config with custom nested values."""
        config = Config(
            environment="production",
            debug=True,
            packages_feed=FeedConfig(type="custom_feed", enabled=False),
            packages_registry=RegistryConfig(type="custom_registry", enabled=True),
            logging=LoggingConfig(level="ERROR", file_path="/var/log/custom.log")
        )
        
        assert config.environment == "production"
        assert config.debug is True
        assert config.packages_feed.type == "custom_feed"
        assert config.packages_feed.enabled is False
        assert config.packages_registry.type == "custom_registry"
        assert config.packages_registry.enabled is True
        assert config.logging.level == "ERROR"
        assert config.logging.file_path == "/var/log/custom.log"