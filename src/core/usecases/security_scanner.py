"""Security scanner use case."""

import uuid
from datetime import datetime, timezone
from typing import List
import logging

from src.core.entities import ScanResult, ScanStatus, NotificationEvent, NotificationChannel
from src.core.interfaces import (
    PackagesFeed,
    PackagesRegistryService,
    NotificationService,
    StorageService
)


logger = logging.getLogger(__name__)


class SecurityScannerError(Exception):
    """Exception raised by SecurityScanner."""
    pass


class SecurityScanner:
    """
    Main use case orchestrating the security scanning pipeline.
    
    This class implements the core business logic:
    1. Fetch malicious packages from feed
    2. Block them in registries
    3. Check for existing packages
    4. Notify SOC and log results
    """
    
    def __init__(
        self,
        packages_feed: PackagesFeed,
        registry_service: PackagesRegistryService,
        notification_service: NotificationService,
        storage_service: StorageService
    ):
        """Initialize security scanner with required services."""
        self._packages_feed = packages_feed
        self._registry_service = registry_service
        self._notification_service = notification_service
        self._storage_service = storage_service
    
    async def execute_scan(self) -> ScanResult:
        """
        Execute a complete security scan.
        
        Returns:
            ScanResult with details of the scan execution
            
        Raises:
            SecurityScannerError: If critical scan operations fail
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        errors = []
        
        logger.info(f"Starting security scan {scan_id}")
        
        try:
            # Step 1: Fetch malicious packages from feed
            logger.info("Fetching malicious packages from feed")
            malicious_packages = await self._packages_feed.fetch_malicious_packages()
            logger.info(f"Found {len(malicious_packages)} malicious packages in feed")
            
            # Step 2: Check which packages are already present in registry
            logger.info("Checking for existing packages in registry")
            existing_packages = await self._registry_service.check_existing_packages(malicious_packages)
            logger.info(f"Found {len(existing_packages)} packages already present in registry")
            
            # Step 3: Block new packages (those not already present)
            new_packages = [pkg for pkg in malicious_packages if pkg not in existing_packages]
            blocked_packages = []
            
            if new_packages:
                logger.info(f"Blocking {len(new_packages)} new malicious packages")
                blocked_packages = await self._registry_service.block_packages(new_packages)
                logger.info(f"Successfully blocked {len(blocked_packages)} packages")
            else:
                logger.info("No new packages to block")
            
            # Step 4: Create scan result
            end_time = datetime.now(timezone.utc)
            scan_result = ScanResult(
                scan_id=scan_id,
                timestamp=start_time,
                status=ScanStatus.SUCCESS,
                packages_scanned=len(malicious_packages),
                malicious_packages_found=malicious_packages,
                packages_blocked=blocked_packages,
                malicious_packages_list=existing_packages,
                errors=errors,
                execution_duration_seconds=(end_time - start_time).total_seconds()
            )
            
            # Step 5: Store scan result
            try:
                await self._storage_service.store_scan_result(scan_result)
                await self._storage_service.store_malicious_packages(malicious_packages)
                logger.info("Scan result stored successfully")
            except Exception as e:
                logger.error(f"Failed to store scan result: {e}")
                errors.append(f"Storage error: {str(e)}")
            
            # Step 6: Send notification
            await self._send_notification(scan_result)
            
            logger.info(f"Security scan {scan_id} completed successfully")
            return scan_result
            
        except Exception as e:
            logger.error(f"Security scan {scan_id} failed: {e}")
            end_time = datetime.now(timezone.utc)
            
            # Create failed scan result
            failed_result = ScanResult(
                scan_id=scan_id,
                timestamp=start_time,
                status=ScanStatus.FAILED,
                packages_scanned=0,
                malicious_packages_found=[],
                packages_blocked=[],
                malicious_packages_list=[],
                errors=errors + [str(e)],
                execution_duration_seconds=(end_time - start_time).total_seconds()
            )
            
            # Try to store failed result and notify
            try:
                await self._storage_service.store_scan_result(failed_result)
                await self._send_notification(failed_result)
            except Exception as storage_error:
                logger.error(f"Failed to store failed scan result: {storage_error}")
            
            raise SecurityScannerError(f"Scan failed: {e}") from e
    
    async def _send_notification(self, scan_result: ScanResult) -> None:
        """Send notification based on scan result."""
        try:
            # Determine notification channels (could be configurable)
            channels = [NotificationChannel.SLACK, NotificationChannel.EMAIL]
            
            notification_event = NotificationEvent.create_threat_notification(
                event_id=str(uuid.uuid4()),
                scan_result=scan_result,
                channels=channels,
                metadata={
                    "scanner_version": "1.0.0",
                    "environment": "production"  # Could be configurable
                }
            )
            
            success = await self._notification_service.send_notification(notification_event)
            if success:
                logger.info("Notification sent successfully")
            else:
                logger.warning("Failed to send notification")
                
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            # Don't raise - notification failure shouldn't fail the entire scan
    
    async def health_check(self) -> dict:
        """
        Perform health check on all services.
        
        Returns:
            Dictionary with health status of all services
        """
        health_status = {}
        
        try:
            health_status["packages_feed"] = await self._packages_feed.health_check()
        except Exception as e:
            health_status["packages_feed"] = False
            logger.error(f"Packages feed health check failed: {e}")
        
        try:
            health_status["registry_service"] = await self._registry_service.health_check()
        except Exception as e:
            health_status["registry_service"] = False
            logger.error(f"Registry service health check failed: {e}")
        
        try:
            health_status["notification_service"] = await self._notification_service.health_check()
        except Exception as e:
            health_status["notification_service"] = False
            logger.error(f"Notification service health check failed: {e}")
        
        try:
            health_status["storage_service"] = await self._storage_service.health_check()
        except Exception as e:
            health_status["storage_service"] = False
            logger.error(f"Storage service health check failed: {e}")
        
        health_status["overall"] = all(health_status.values())
        return health_status