"""Service factory for creating provider instances based on configuration."""

import logging
from typing import Any, Dict

from src.config import Config
from src.core.interfaces import (
    PackagesFeed,
    PackagesRegistryService,
    NotificationService,
    StorageService
)
from src.providers.feeds import OSVFeed
from src.providers.registries import JFrogRegistry
from src.providers.notifications import CompositeNotifier
from src.providers.storage import FileStorage, MemoryStorage, DatabaseStorage


logger = logging.getLogger(__name__)


class ServiceFactoryError(Exception):
    """Exception raised by ServiceFactory."""
    pass


class ServiceFactory:
    """Factory for creating service instances based on configuration."""
    
    def __init__(self, config: Config):
        """
        Initialize service factory with configuration.
        
        Args:
            config: Application configuration
        """
        self.config = config
    
    def create_packages_feed(self) -> PackagesFeed:
        """
        Create packages feed provider based on configuration.
        
        Returns:
            PackagesFeed instance
            
        Raises:
            ServiceFactoryError: If provider creation fails
        """
        logger.debug(f"Creating packages feed provider: {self.config.packages_feed.type}")
        
        try:
            if self.config.packages_feed.type.lower() == "osv":
                return OSVFeed(
                    bucket_name=self.config.packages_feed.config.get("bucket_name", "osv-vulnerabilities"),
                    timeout_seconds=self.config.packages_feed.config.get("timeout_seconds", 30),
                    max_retries=self.config.packages_feed.config.get("max_retries", 3),
                    retry_delay=self.config.packages_feed.config.get("retry_delay", 1.0)
                )
            else:
                raise ServiceFactoryError(f"Unknown packages feed type: {self.config.packages_feed.type}")
        
        except Exception as e:
            raise ServiceFactoryError(f"Failed to create packages feed: {e}") from e
    
    def create_packages_registry(self) -> PackagesRegistryService:
        """
        Create packages registry service based on configuration.
        
        Returns:
            PackagesRegistryService instance
            
        Raises:
            ServiceFactoryError: If provider creation fails
        """
        logger.debug(f"Creating packages registry service: {self.config.packages_registry.type}")
        
        # Check if packages registry is disabled
        if not self.config.packages_registry.enabled:
            logger.info("Packages registry is disabled, creating null registry")
            return self._create_null_registry()
        
        try:
            if self.config.packages_registry.type.lower() == "jfrog":
                if not self.config.jfrog_base_url:
                    raise ServiceFactoryError("JFrog base URL not configured")
                
                # Extract repository discovery configuration
                repository_config = self.config.packages_registry.config.get("repository_discovery", {})
                ecosystem_overrides = repository_config.get("ecosystem_overrides", {})
                cache_ttl_seconds = repository_config.get("cache_ttl_seconds", 3600)
                
                return JFrogRegistry(
                    base_url=self.config.jfrog_base_url,
                    username=self.config.jfrog_username,
                    password=self.config.jfrog_password,
                    api_key=self.config.jfrog_api_key,
                    timeout_seconds=self.config.packages_registry.config.get("timeout_seconds", 30),
                    max_retries=self.config.packages_registry.config.get("max_retries", 3),
                    retry_delay=self.config.packages_registry.config.get("retry_delay", 1.0),
                    repository_overrides=ecosystem_overrides,
                    cache_ttl_seconds=cache_ttl_seconds
                )
            else:
                raise ServiceFactoryError(f"Unknown packages registry type: {self.config.packages_registry.type}")
        
        except Exception as e:
            raise ServiceFactoryError(f"Failed to create packages registry: {e}") from e
    
    def create_notification_service(self) -> NotificationService:
        """
        Create notification service based on configuration.
        
        Returns:
            NotificationService instance
            
        Raises:
            ServiceFactoryError: If provider creation fails
        """
        logger.debug(f"Creating notification service: {self.config.notification_service.type}")
        
        # Check if notification service is disabled
        if not self.config.notification_service.enabled:
            logger.info("Notification service is disabled, creating null notifier")
            return self._create_null_notifier()
        
        try:
            service_type = self.config.notification_service.type.lower()
            
            if service_type == "null":
                return self._create_null_notifier()
            elif service_type == "composite":
                # For future implementations like MS Teams
                return self._create_null_notifier()
            else:
                logger.warning(f"Unknown notification service type: {self.config.notification_service.type}, using null notifier")
                return self._create_null_notifier()
        
        except Exception as e:
            logger.warning(f"Failed to create notification service, using null notifier: {e}")
            return self._create_null_notifier()

    def _create_null_notifier(self) -> NotificationService:
        """Create a null notifier that does nothing (for disabled notifications)."""
        from ..providers.notifications.null_notifier import NullNotifier
        return NullNotifier()
    
    def _create_null_registry(self) -> PackagesRegistryService:
        """Create a null registry that does nothing (for disabled registry)."""
        from ..providers.registries.null_registry import NullRegistry
        return NullRegistry()
    
    def create_storage_service(self) -> StorageService:
        """
        Create storage service based on configuration.
        
        Returns:
            StorageService instance
            
        Raises:
            ServiceFactoryError: If provider creation fails
        """
        logger.debug(f"Creating storage service: {self.config.storage_service.type}")
        
        try:
            storage_type = self.config.storage_service.type.lower()
            
            if storage_type == "file":
                return FileStorage(
                    data_directory=self.config.storage_service.config.get("data_directory", "scan_results")
                )
            elif storage_type == "memory":
                return MemoryStorage(
                    max_scan_results=self.config.storage_service.config.get("max_scan_results", 1000),
                    clear_on_init=self.config.storage_service.config.get("clear_on_init", False)
                )
            elif storage_type == "database" or storage_type == "sqlite":
                db_path = self.config.storage_service.config.get("database_path", "data/security_scanner.db")
                return DatabaseStorage(
                    database_path=db_path,
                    connection_timeout=self.config.storage_service.config.get("connection_timeout", 30.0),
                    max_connections=self.config.storage_service.config.get("max_connections", 10),
                    in_memory=True if db_path == ":memory:" else False,
                )
            else:
                raise ServiceFactoryError(f"Unknown storage service type: {self.config.storage_service.type}")
        
        except Exception as e:
            raise ServiceFactoryError(f"Failed to create storage service: {e}") from e
    
