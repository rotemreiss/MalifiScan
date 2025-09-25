"""Main application entry point for CLI usage."""

import asyncio
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Any

from .config import ConfigLoader, Config, ConfigError
from .core.usecases import SecurityScanner
from .core.usecases.scan_results import ScanResultsManager
from .core.usecases.security_analysis import SecurityAnalysisUseCase
from .core.usecases.package_management import PackageManagementUseCase
from .core.usecases.data_management import DataManagementUseCase
from .core.usecases.health_management import HealthManagementUseCase
from .core.usecases.test_data_management import TestDataManagementUseCase
from .core.usecases.registry_management import RegistryManagementUseCase
from .core.usecases.feed_management import FeedManagementUseCase
from .core.usecases.proactive_security import ProactiveSecurityUseCase
from .factories import ServiceFactory


def setup_logging(config: Config) -> None:
    """Setup logging configuration."""
    log_format = config.logging.format
    log_level = getattr(logging, config.logging.level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    console_handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    # File logging if configured
    if config.logging.file_path:
        file_path = Path(config.logging.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=config.logging.max_file_size_mb * 1024 * 1024,
            backupCount=config.logging.backup_count
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


class SecurityScannerApp:
    """Main application class for the Security Scanner."""
    
    def __init__(self, config_file: str = "config.yaml", env_file: str = ".env"):
        """
        Initialize the Security Scanner application.
        
        Args:
            config_file: Path to configuration file
            env_file: Path to environment file
        """
        self.config_file = config_file
        self.env_file = env_file
        self.config: Optional[Config] = None
        self.services: dict = {}
        self.security_scanner: Optional[SecurityScanner] = None
        
        # Use cases
        self.security_analysis: Optional[SecurityAnalysisUseCase] = None
        self.package_management: Optional[PackageManagementUseCase] = None
        self.data_management: Optional[DataManagementUseCase] = None
        self.health_management: Optional[HealthManagementUseCase] = None
        self.test_data_management: Optional[TestDataManagementUseCase] = None
        self.scan_results_manager: Optional[ScanResultsManager] = None
        self.registry_management: Optional[RegistryManagementUseCase] = None
        self.feed_management: Optional[FeedManagementUseCase] = None
        self.proactive_security: Optional[ProactiveSecurityUseCase] = None
        
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self) -> None:
        """Initialize the application."""
        try:
            # Load configuration
            self.logger.info("Loading configuration...")
            config_loader = ConfigLoader(self.config_file, self.env_file, "config.local.yaml")
            self.config = config_loader.load()
            
            # Setup logging
            setup_logging(self.config)
            self.logger.info(f"Application initialized in {self.config.environment} environment")
            
            # Create services
            self.logger.info("Creating services...")
            service_factory = ServiceFactory(self.config)
            self.services = {
                "packages_feed": service_factory.create_packages_feed(),
                "packages_registry": service_factory.create_packages_registry(),
                "notification_service": service_factory.create_notification_service(),
                "storage_service": service_factory.create_storage_service()
            }
            
            # Create security scanner
            self.security_scanner = SecurityScanner(
                packages_feed=self.services["packages_feed"],
                registry_service=self.services["packages_registry"],
                notification_service=self.services["notification_service"],
                storage_service=self.services["storage_service"]
            )
            
            # Create use cases
            self.logger.info("Creating use cases...")
            self.security_analysis = SecurityAnalysisUseCase(
                packages_feed=self.services["packages_feed"],
                registry_service=self.services["packages_registry"],
                storage_service=self.services["storage_service"],
                notification_service=self.services["notification_service"]
            )
            
            self.package_management = PackageManagementUseCase(
                registry_service=self.services["packages_registry"],
                storage_service=self.services["storage_service"]
            )
            
            self.data_management = DataManagementUseCase(
                storage_service=self.services["storage_service"],
                packages_feed=self.services["packages_feed"]
            )
            
            self.health_management = HealthManagementUseCase(
                services=self.services
            )
            
            self.test_data_management = TestDataManagementUseCase(
                storage_service=self.services["storage_service"]
            )
            
            self.scan_results_manager = ScanResultsManager(
                storage_service=self.services["storage_service"],
                registry_service=self.services["packages_registry"]
            )
            
            self.registry_management = RegistryManagementUseCase(
                registry_service=self.services["packages_registry"]
            )
            
            self.feed_management = FeedManagementUseCase(
                packages_feed=self.services["packages_feed"]
            )
            
            self.proactive_security = ProactiveSecurityUseCase(
                packages_feed=self.services["packages_feed"],
                registry_service=self.services["packages_registry"]
            )
            
            self.logger.info("Application initialization complete")
            
        except ConfigError as e:
            self.logger.error(f"Configuration error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize application: {e}")
            raise
    
    async def run_single_scan(self) -> bool:
        """
        Run a single security scan.
        
        Returns:
            True if scan completed successfully, False otherwise
        """
        try:
            self.logger.info("Starting single security scan...")
            
            if not self.security_scanner:
                raise RuntimeError("Security scanner not initialized")
            
            # Run the scan
            scan_result = await self.security_scanner.execute_scan()
            
            if scan_result.is_successful:
                self.logger.info(f"Scan completed successfully: {scan_result.scan_id}")
                self.logger.info(f"Packages scanned: {scan_result.packages_scanned}")
                self.logger.info(f"Malicious packages found: {len(scan_result.malicious_packages_found)}")
                self.logger.info(f"Packages blocked: {len(scan_result.packages_blocked)}")
                self.logger.info(f"New threats: {scan_result.new_threats_count}")
                return True
            else:
                self.logger.error(f"Scan failed with status: {scan_result.status.value}")
                if scan_result.errors:
                    for error in scan_result.errors:
                        self.logger.error(f"Error: {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            return False
    
    async def get_status(self) -> dict:
        """
        Get application status.
        
        Returns:
            Dictionary containing status information
        """
        try:
            status = {
                "application": "Security Scanner",
                "environment": self.config.environment if self.config else "unknown",
                "services": {}
            }
            
            if self.services:
                # Check service health
                for service_name, service in self.services.items():
                    if hasattr(service, 'health_check'):
                        try:
                            await service.health_check()
                            status["services"][service_name] = "healthy"
                        except Exception as e:
                            status["services"][service_name] = f"unhealthy: {e}"
                    else:
                        status["services"][service_name] = "unknown"
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error getting status: {e}")
            return {"error": str(e)}
    
    async def security_crossref_analysis(self, hours: int = 6, ecosystem: Optional[str] = None, limit: Optional[int] = None, save_report: bool = True, send_notifications: bool = True) -> dict:
        """
        Cross-reference OSV malicious packages with JFrog registry.
        
        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (None for all available ecosystems)
            limit: Maximum number of malicious packages to check
            save_report: Whether to save the scan result to storage (default: True)
            send_notifications: Whether to send notifications for critical matches (default: True)
            
        Returns:
            Dictionary containing analysis results
        """
        if not self.security_analysis:
            raise RuntimeError("Application not initialized")
        
        return await self.security_analysis.crossref_analysis(hours, ecosystem, limit, save_report, send_notifications)
    
    async def security_crossref_analysis_with_blocking(
        self, 
        hours: int = 6, 
        ecosystem: Optional[str] = None, 
        limit: Optional[int] = None, 
        save_report: bool = True,
        block_packages: bool = False,
        send_notifications: bool = True,
        progress_callback: Optional[Any] = None
    ) -> dict:
        """
        Cross-reference OSV malicious packages with JFrog registry, with optional proactive blocking.
        
        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (default: npm)
            limit: Maximum number of malicious packages to check
            save_report: Whether to save the scan result to storage (default: True)
            block_packages: Whether to block malicious packages before analysis (default: False)
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary containing analysis results including blocking information
        """
        if not self.security_analysis:
            raise RuntimeError("Application not initialized")
        
        return await self.security_analysis.crossref_analysis_with_blocking(
            hours, ecosystem, limit, save_report, block_packages, send_notifications, progress_callback
        )
    
    async def block_package_in_registry(self, package_name: str, ecosystem: str = "npm", version: str = "*") -> dict:
        """
        Block a package in JFrog registry.
        
        Args:
            package_name: Name of the package to block
            ecosystem: Package ecosystem (default: npm)
            version: Package version (default: *)
            
        Returns:
            Dictionary containing block operation results
        """
        if not self.package_management:
            raise RuntimeError("Application not initialized")
        
        return await self.package_management.block_package(package_name, ecosystem, version)

    async def search_package_in_registry(self, package_name: str, ecosystem: str = "npm") -> dict:
        """
        Search for a package in JFrog registry and return structured results.
        
        Args:
            package_name: Name of the package to search for
            ecosystem: Package ecosystem (default: npm)
            
        Returns:
            Dictionary containing search results and metadata
        """
        if not self.package_management:
            raise RuntimeError("Application not initialized")
        
        return await self.package_management.search_package(package_name, ecosystem)
    
    async def get_service_health_status(self) -> dict:
        """
        Check health of all services.
        
        Returns:
            Dictionary containing health status for each service
        """
        if not self.health_management:
            raise RuntimeError("Application not initialized")
        
        return await self.health_management.get_service_health_status()
    
    async def get_recent_scan_summaries(self, limit: int = 3) -> dict:
        """
        Get recent scan summaries.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            Dictionary containing scan summaries and metadata
        """
        if not self.scan_results_manager:
            raise RuntimeError("Application not initialized")
        
        try:
            summaries = await self.scan_results_manager.get_recent_scans(limit)
            return {
                "success": True,
                "summaries": summaries,
                "count": len(summaries)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "summaries": [],
                "count": 0
            }
    
    async def get_scan_result_details(self, scan_id: str) -> dict:
        """
        Get detailed scan result with findings.
        
        Args:
            scan_id: Unique identifier of the scan
            
        Returns:
            Dictionary containing detailed scan result
        """
        if not self.scan_results_manager:
            raise RuntimeError("Application not initialized")
        
        try:
            details = await self.scan_results_manager.get_scan_details(scan_id)
            if not details:
                return {
                    "success": False,
                    "error": f"Scan not found: {scan_id}",
                    "details": None
                }
            
            return {
                "success": True,
                "details": details,
                "scan_result": details.scan_result,
                "findings": details.findings,
                "found_matches": details.found_matches,
                "safe_packages": details.safe_packages,
                "not_found_count": details.not_found_count
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "details": None
            }
    
    async def fetch_packages_feed_data(self, ecosystem: Optional[str] = None, limit: int = 100, hours: int = 48) -> dict:
        """
        Fetch fresh malicious packages from packages feed.
        
        Args:
            ecosystem: Filter by ecosystem
            limit: Maximum number of packages to fetch
            hours: Fetch packages modified within the last N hours
            
        Returns:
            Dictionary containing fetched packages and metadata
        """
        if not self.data_management:
            raise RuntimeError("Application not initialized")
        
        return await self.data_management.fetch_osv_packages(ecosystem, limit, hours)
    
    async def create_test_malicious_packages(self) -> dict:
        """
        Create test malicious packages for testing purposes.
        
        Returns:
            Dictionary containing creation results
        """
        if not self.test_data_management:
            raise RuntimeError("Application not initialized")
        
        return await self.test_data_management.create_test_malicious_packages()

    async def cleanup(self) -> None:
        """Cleanup application resources."""
        try:
            self.logger.info("Cleaning up application resources...")
            
            # Cleanup services
            for service_name, service in self.services.items():
                if hasattr(service, 'cleanup'):
                    try:
                        await service.cleanup()
                        self.logger.debug(f"Cleaned up {service_name}")
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up {service_name}: {e}")
            
            self.logger.info("Application cleanup complete")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")


async def main() -> int:
    """Main entry point for the CLI application."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Scanner CLI Tool")
    parser.add_argument("--config", default="config.yaml", help="Configuration file path")
    parser.add_argument("--env", default=".env", help="Environment file path")
    parser.add_argument("--scan", action="store_true", help="Run a single scan and exit")
    parser.add_argument("--status", action="store_true", help="Show status and exit")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Setup basic logging for startup
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger = logging.getLogger(__name__)
    app = None
    
    try:
        # Initialize application
        app = SecurityScannerApp(config_file=args.config, env_file=args.env)
        await app.initialize()
        
        if args.status:
            # Show status and exit
            status = await app.get_status()
            print("Application Status:")
            for key, value in status.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for sub_key, sub_value in value.items():
                        print(f"    {sub_key}: {sub_value}")
                else:
                    print(f"  {key}: {value}")
            return 0
        
        elif args.scan:
            # Run single scan and exit
            success = await app.run_single_scan()
            return 0 if success else 1
        
        else:
            # Default: run single scan
            success = await app.run_single_scan()
            return 0 if success else 1
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
        return 130
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1
    finally:
        if app:
            await app.cleanup()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))