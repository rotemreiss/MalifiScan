"""Tests for configuration system."""

import pytest
import tempfile
import os
from pathlib import Path

from src.config import ConfigLoader, Config, ConfigError, ConfigValidationError


class TestConfigLoader:
    """Tests for ConfigLoader."""
    
    def test_load_default_config(self):
        """Test loading with default configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config file
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
environment: test
""")
            
            loader = ConfigLoader(str(config_file), local_config_file=None, load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            assert config.environment == "test"
            assert config.packages_feed.type == "osv"
            assert config.packages_registry.type == "jfrog"
            assert config.packages_registry.enabled is False  # Should be disabled by default
    
    def test_load_with_env_override(self):
        """Test loading with environment variable overrides."""
        import os
        from unittest.mock import patch
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create config file
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
environment: development
debug: false
packages_registry:
  enabled: false
notification_service:
  enabled: false
""")
            
            # Test with environment variable overrides directly
            with patch.dict(os.environ, {
                'ENVIRONMENT': 'production',
                'DEBUG': 'true',
                'OSV_API_BASE_URL': 'https://custom-osv.example.com'
            }):
                loader = ConfigLoader(str(config_file), local_config_file=None, load_env_file=False, use_env_vars=True)
                config = loader.load()
                
                assert config.environment == "production"
                assert config.debug is True
                assert config.osv_api_base_url == "https://custom-osv.example.com"
    
    def test_load_nonexistent_config_file(self):
        """Test loading when config file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            nonexistent_file = Path(temp_dir) / "nonexistent.yaml"
            
            loader = ConfigLoader(str(nonexistent_file), local_config_file=None, load_env_file=False, use_env_vars=False)
            config = loader.load()
            
            # Should load with defaults
            assert config.environment == "development"
            assert config.packages_feed.type == "osv"
    
    def test_validation_jfrog_missing_credentials(self):
        """Test validation error when JFrog credentials are missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("""
packages_registry:
  type: jfrog
  enabled: true
""")
            
            loader = ConfigLoader(str(config_file), local_config_file=None, load_env_file=False, use_env_vars=False)
            
            with pytest.raises(ConfigError, match="JFrog base URL is required"):
                loader.load()
    
class TestConfig:
    """Tests for Config model."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.environment == "development"
        assert config.debug is False
        assert config.packages_feed.type == "osv"
        assert config.packages_registry.type == "jfrog"
    
    def test_config_with_custom_values(self):
        """Test configuration with custom values."""
        config = Config(
            environment="production",
            debug=True,
            jfrog_base_url="https://my-jfrog.example.com"
        )
        
        assert config.environment == "production"
        assert config.debug is True
        assert config.jfrog_base_url == "https://my-jfrog.example.com"