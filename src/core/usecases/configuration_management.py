"""Configuration Management Use Case for handling configuration initialization and validation."""

from typing import Dict, Any, Tuple, List
from pathlib import Path
import logging
import shutil
from src.config.config_loader import ConfigLoader
from src.config import Config


class ConfigurationManagementUseCase:
    """Use case for configuration management operations."""
    
    def __init__(self, config_file: str = "config.yaml", env_file: str = ".env", local_config_file: str = "config.local.yaml"):
        """
        Initialize the configuration management use case.
        
        Args:
            config_file: Path to main configuration file
            env_file: Path to environment variables file
            local_config_file: Path to local configuration overrides file
        """
        self.config_file = config_file
        self.env_file = env_file
        self.local_config_file = local_config_file
        self.logger = logging.getLogger(__name__)
    
    async def initialize_configuration(self, overwrite_existing: bool = False) -> Tuple[bool, str]:
        """
        Initialize local configuration files from templates.
        
        Args:
            overwrite_existing: Whether to overwrite existing files
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            self.logger.info("Initializing local configuration files...")
            messages = []
            
            # Handle config.local.yaml
            local_config_path = Path(self.local_config_file)
            if local_config_path.exists() and not overwrite_existing:
                return False, f"{self.local_config_file} already exists. Use overwrite_existing=True to replace it."
            
            example_local_config = Path(f"{self.local_config_file}.example")
            if example_local_config.exists():
                shutil.copy2(example_local_config, local_config_path)
                messages.append(f"Created {self.local_config_file} from template")
            else:
                # Create a basic config.local.yaml file
                basic_config = """# Local Configuration Override
# This file contains user-specific settings that override config.yaml
# Add your customizations here

# Example overrides:
# debug: true
# environment: development

# packages_registry:
#   enabled: true
#   config:
#     timeout_seconds: 60

# storage_service:
#   type: file
#   config:
#     data_directory: "my_scan_results"

# logging:
#   level: "DEBUG"
#   file_path: "logs/my_debug.log"
"""
                with open(local_config_path, 'w') as f:
                    f.write(basic_config)
                messages.append(f"Created basic {self.local_config_file}")
            
            # Handle .env file
            env_path = Path(self.env_file)
            if env_path.exists() and not overwrite_existing:
                messages.append(f"Skipped {self.env_file} (already exists)")
            else:
                env_created, env_message = self._create_env_file(env_path)
                messages.append(env_message)
            
            success_message = "Configuration initialization complete!\n" + "\n".join(f"• {msg}" for msg in messages)
            return True, success_message
            
        except Exception as e:
            self.logger.error(f"Error initializing configuration: {e}")
            return False, f"Error initializing configuration: {e}"
    
    def _create_env_file(self, env_path: Path) -> Tuple[bool, str]:
        """
        Create .env file from template.
        
        Args:
            env_path: Path where to create the .env file
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            example_env = Path(".env.example")
            if example_env.exists():
                shutil.copy2(example_env, env_path)
                return True, f"Created {env_path.name} from template"
            else:
                # Create a basic .env file
                basic_env = """# Security Scanner Environment Variables
# Copy and configure according to your environment

# Application Configuration
ENVIRONMENT=development
DEBUG=false

# JFrog Artifactory Configuration
JFROG_BASE_URL=https://your-company.jfrog.io
JFROG_USERNAME=your-username
JFROG_PASSWORD=your-password
# OR use API key authentication (recommended):
# JFROG_API_KEY=your-api-key

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE_PATH=logs/security_scanner.log
"""
                with open(env_path, 'w') as f:
                    f.write(basic_env)
                return True, f"Created basic {env_path.name} file"
        except Exception as e:
            self.logger.error(f"Error creating .env file: {e}")
            return False, f"Error creating .env file: {e}"
    
    async def get_configuration_summary(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Get current configuration summary from all sources.
        
        Returns:
            Tuple of (success: bool, config_summary: Dict[str, Any])
        """
        try:
            self.logger.debug("Loading configuration summary...")
            
            # Load configuration
            config_loader = ConfigLoader(self.config_file, self.env_file, self.local_config_file)
            config = config_loader.load()
            
            # Build configuration summary
            config_summary = {
                "settings": {
                    "environment": config.environment,
                    "debug": config.debug,
                    "osv_feed": {
                        "type": config.packages_feed.type,
                        "enabled": config.packages_feed.enabled
                    },
                    "registry": {
                        "type": config.packages_registry.type,
                        "enabled": config.packages_registry.enabled
                    },
                    "storage": {
                        "type": config.storage_service.type,
                        "enabled": config.storage_service.enabled
                    },
                    "notifications": {
                        "type": config.notification_service.type,
                        "enabled": config.notification_service.enabled
                    },
                    "log_level": config.logging.level
                },
                "environment_vars": {
                    "jfrog_url": "***configured***" if config.jfrog_base_url else "not set",
                    "jfrog_username": "***configured***" if config.jfrog_username else "not set",
                    "jfrog_api_key": "***configured***" if config.jfrog_api_key else "not set"
                },
                "files": self._get_configuration_files_status()
            }
            
            return True, config_summary
            
        except Exception as e:
            self.logger.error(f"Error getting configuration summary: {e}")
            return False, {}
    
    def _get_configuration_files_status(self) -> Dict[str, Dict[str, str]]:
        """
        Get status of configuration files.
        
        Returns:
            Dictionary with file status information
        """
        files_to_check = [
            ("config.yaml", "Base configuration"),
            (self.local_config_file, "Local overrides"),
            (self.env_file, "Environment variables"),
            (".env.example", "Environment template")
        ]
        
        files_status = {}
        for filename, purpose in files_to_check:
            path = Path(filename)
            files_status[filename] = {
                "exists": path.exists(),
                "purpose": purpose,
                "status": "Found" if path.exists() else "Missing"
            }
        
        return files_status
    
    async def validate_configuration(self) -> Tuple[bool, List[Dict[str, str]]]:
        """
        Validate current configuration.
        
        Returns:
            Tuple of (success: bool, validation_results: List[Dict[str, str]])
        """
        try:
            self.logger.info("Validating configuration...")
            
            # Load configuration and check for issues
            config_loader = ConfigLoader(self.config_file, self.env_file, self.local_config_file)
            
            try:
                config = config_loader.load()
                validation_results = [{"status": "✅", "message": "Configuration loaded successfully"}]
            except Exception as e:
                return False, [{"status": "❌", "message": f"Configuration loading failed: {e}"}]
            
            # Validation checks
            if config.packages_registry.enabled:
                if not config.jfrog_base_url:
                    validation_results.append({"status": "❌", "message": "JFrog registry enabled but JFROG_BASE_URL not set"})
                elif not (config.jfrog_api_key or (config.jfrog_username and config.jfrog_password)):
                    validation_results.append({"status": "❌", "message": "JFrog registry enabled but credentials not configured"})
                else:
                    validation_results.append({"status": "✅", "message": "JFrog registry properly configured"})
            else:
                validation_results.append({"status": "⚠️", "message": "JFrog registry disabled"})
            
            if config.packages_feed.enabled:
                validation_results.append({"status": "✅", "message": "OSV feed enabled"})
            else:
                validation_results.append({"status": "⚠️", "message": "OSV feed disabled"})
            
            # Check storage configuration
            if config.storage_service.type == "database":
                db_path = config.storage_service.config.get("database_path", "data/security_scanner.db")
                db_dir = Path(db_path).parent
                if not db_dir.exists():
                    validation_results.append({"status": "⚠️", "message": f"Database directory '{db_dir}' does not exist"})
                else:
                    validation_results.append({"status": "✅", "message": "Database storage configured"})
            elif config.storage_service.type == "file":
                data_dir = config.storage_service.config.get("data_directory", "scan_results")
                if not Path(data_dir).exists():
                    validation_results.append({"status": "⚠️", "message": f"File storage directory '{data_dir}' does not exist"})
                else:
                    validation_results.append({"status": "✅", "message": "File storage configured"})
            
            # Check for errors
            errors = [r for r in validation_results if r["status"] == "❌"]
            success = len(errors) == 0
            
            return success, validation_results
            
        except Exception as e:
            self.logger.error(f"Error validating configuration: {e}")
            return False, [{"status": "❌", "message": f"Error validating configuration: {e}"}]