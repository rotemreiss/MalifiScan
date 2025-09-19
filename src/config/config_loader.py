"""Configuration loader and models."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

from .exceptions import ConfigError, ConfigValidationError, ConfigFileNotFoundError


class ProviderConfig(BaseModel):
    """Base provider configuration."""
    type: str
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class FeedConfig(ProviderConfig):
    """Packages feed configuration."""
    type: str = "osv"
    

class RegistryConfig(ProviderConfig):
    """Packages registry configuration."""
    type: str = "jfrog"
    enabled: bool = False  # Disabled by default to avoid requiring credentials


class NotificationConfig(ProviderConfig):
    """Notification service configuration."""
    type: str = "null"
    enabled: bool = False  # Disabled by default to avoid requiring credentials
    channels: List[str] = Field(default_factory=list)


class StorageConfig(ProviderConfig):
    """Storage service configuration."""
    type: str = "file"


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size_mb: int = 10
    backup_count: int = 5


class Config(BaseModel):
    """Main application configuration."""
    
    # Environment
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    
    # Services
    packages_feed: FeedConfig = Field(default_factory=FeedConfig)
    packages_registry: RegistryConfig = Field(default_factory=RegistryConfig)
    notification_service: NotificationConfig = Field(default_factory=NotificationConfig)
    storage_service: StorageConfig = Field(default_factory=StorageConfig)
    
    # Logging
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # API Keys and secrets (loaded from environment)
    osv_api_base_url: str = Field(default="https://osv-vulnerabilities.storage.googleapis.com")
    jfrog_base_url: Optional[str] = None
    jfrog_username: Optional[str] = None
    jfrog_password: Optional[str] = None
    jfrog_api_key: Optional[str] = None
    
    class Config:
        env_file_encoding = 'utf-8'
        case_sensitive = False


class ConfigLoader:
    """Configuration loader that handles both YAML and environment variables."""
    
    def __init__(self, config_file: Optional[str] = None, env_file: Optional[str] = None, load_env_file: bool = True, use_env_vars: bool = True):
        """
        Initialize config loader.
        
        Args:
            config_file: Path to YAML config file
            env_file: Path to .env file
            load_env_file: Whether to automatically load .env file
            use_env_vars: Whether to use environment variables for overrides
        """
        self.config_file = config_file or "config.yaml"
        self.env_file = env_file or ".env"
        self.load_env_file = load_env_file
        self.use_env_vars = use_env_vars
    
    def load(self) -> Config:
        """
        Load configuration from files and environment.
        
        Returns:
            Validated Config object
            
        Raises:
            ConfigError: If configuration loading fails
        """
        try:
            # Load environment variables first (if enabled)
            if self.load_env_file and Path(self.env_file).exists():
                load_dotenv(self.env_file)
            
            # Load YAML configuration
            config_data = self._load_yaml_config()
            
            # Override with environment variables (if enabled)
            if self.use_env_vars:
                config_data = self._override_with_env(config_data)
            
            # Validate and create config object
            config = Config(**config_data)
            
            # Perform additional validation
            self._validate_config(config)
            
            return config
            
        except Exception as e:
            raise ConfigError(f"Failed to load configuration: {e}") from e
    
    def _load_yaml_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        config_path = Path(self.config_file)
        
        if not config_path.exists():
            # Return default config if file doesn't exist
            return {}
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML in config file: {e}") from e
        except Exception as e:
            raise ConfigFileNotFoundError(f"Cannot read config file: {e}") from e
    
    def _override_with_env(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Override configuration with environment variables."""
        # Environment variables that should override config
        env_mappings = {
            'ENVIRONMENT': 'environment',
            'DEBUG': 'debug',
            'OSV_API_BASE_URL': 'osv_api_base_url',
            'JFROG_BASE_URL': 'jfrog_base_url',
            'JFROG_USERNAME': 'jfrog_username',
            'JFROG_PASSWORD': 'jfrog_password',
            'JFROG_API_KEY': 'jfrog_api_key',
            'LOG_LEVEL': 'logging.level',
            'LOG_FILE_PATH': 'logging.file_path'
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Handle nested configuration paths
                if '.' in config_path:
                    keys = config_path.split('.')
                    current = config_data
                    for key in keys[:-1]:
                        if key not in current:
                            current[key] = {}
                        current = current[key]
                    
                    # Convert value to appropriate type
                    converted_value = self._convert_env_value(env_value, keys[-1])
                    current[keys[-1]] = converted_value
                else:
                    converted_value = self._convert_env_value(env_value, config_path)
                    config_data[config_path] = converted_value
        
        return config_data
    
    def _convert_env_value(self, value: str, key: str) -> Any:
        """Convert environment variable value to appropriate type."""
        # Boolean values
        if key in ['debug'] or value.lower() in ['true', 'false']:
            return value.lower() == 'true'
        
        # Integer values
        if key in ['email_smtp_port', 'interval_hours', 'max_file_size_mb', 'backup_count']:
            try:
                return int(value)
            except ValueError:
                return value
        
        # List values (comma-separated)
        if key in ['email_to_addresses']:
            return [item.strip() for item in value.split(',') if item.strip()]
        
        return value
    
    def _validate_config(self, config: Config) -> None:
        """Perform additional configuration validation."""
        # Validate JFrog configuration
        if config.packages_registry.enabled and config.packages_registry.type == "jfrog":
            if not config.jfrog_base_url:
                raise ConfigValidationError("JFrog base URL is required when JFrog registry is enabled")
            
            if not (config.jfrog_api_key or (config.jfrog_username and config.jfrog_password)):
                raise ConfigValidationError(
                    "JFrog API key or username/password is required when JFrog registry is enabled"
                )