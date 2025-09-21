"""Security Analysis Use Case for cross-referencing OSV data with package registry."""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Callable
import logging

from ..entities.malicious_package import MaliciousPackage
from ..entities.scan_result import ScanResult, ScanStatus
from ..entities.registry_package_match import RegistryPackageMatchBuilder
from ..entities.notification_event import NotificationEvent, NotificationChannel
from ..interfaces.packages_feed import PackagesFeed
from ..interfaces.packages_registry_service import PackagesRegistryService
from ..interfaces.storage_service import StorageService


class SecurityAnalysisUseCase:
    """Use case for security analysis operations."""
    
    def __init__(
        self,
        packages_feed: PackagesFeed,
        registry_service: PackagesRegistryService,
        storage_service: Optional[StorageService] = None,
        notification_service: Optional[Any] = None
    ):
        """
        Initialize the security analysis use case.
        
        Args:
            packages_feed: Service for fetching malicious package data
            registry_service: Service for interacting with package registry
            storage_service: Service for storing scan results (optional)
            notification_service: Service for sending notifications (optional)
        """
        self.packages_feed = packages_feed
        self.registry_service = registry_service
        self.storage_service = storage_service
        self.notification_service = notification_service
        self.logger = logging.getLogger(__name__)
    
    async def crossref_analysis(
        self, 
        hours: int = 6, 
        ecosystem: str = "npm", 
        limit: Optional[int] = None,
        save_report: bool = True,
        send_notifications: bool = True
    ) -> Dict[str, Any]:
        """
        Cross-reference OSV malicious packages with JFrog registry.
        
        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (default: npm)
            limit: Maximum number of malicious packages to check
            save_report: Whether to save the scan result to storage (default: True)
            send_notifications: Whether to send notifications for critical matches (default: True)
            
        Returns:
            Dictionary containing analysis results
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        errors = []
        
        try:
            self.logger.debug(f"Starting security cross-reference analysis for {ecosystem} packages from last {hours} hours (scan_id: {scan_id})")
            
            # Step 1: Fetch recent malicious packages from OSV
            malicious_packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=limit,
                hours=hours
            )
            
            # Filter by ecosystem since OSV returns all ecosystems
            malicious_packages = [pkg for pkg in malicious_packages if pkg.ecosystem.lower() == ecosystem.lower()]
            
            if not malicious_packages:
                self.logger.info(f"No malicious {ecosystem} packages found in the last {hours} hours")
                
                # Save empty scan result if storage is available and save_report is True
                if save_report and self.storage_service:
                    await self._save_scan_result(
                        scan_id, start_time, ScanStatus.SUCCESS, 0, [], [], [], errors
                    )
                
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "total_osv_packages": 0,
                    "filtered_packages": 0,
                    "found_matches": [],
                    "safe_packages": [],
                    "errors": [],
                    "not_found_count": 0,
                    "report_saved": save_report and self.storage_service is not None
                }
            
            self.logger.debug(f"Found {len(malicious_packages)} malicious {ecosystem} packages to check")
            
            # Step 2: Check each malicious package against JFrog
            
            # Check JFrog health first
            if not await self.registry_service.health_check():
                self.logger.error("JFrog registry is not accessible")
                error_msg = "JFrog registry is not accessible"
                errors.append(error_msg)
                
                # Save failed scan result if storage is available and save_report is True
                if save_report and self.storage_service:
                    await self._save_scan_result(
                        scan_id, start_time, ScanStatus.FAILED, len(malicious_packages), 
                        malicious_packages, [], [], errors
                    )
                
                return {
                    "success": False,
                    "scan_id": scan_id,
                    "error": error_msg,
                    "total_osv_packages": len(malicious_packages),
                    "filtered_packages": len(malicious_packages),
                    "found_matches": [],
                    "safe_packages": [],
                    "errors": errors,
                    "not_found_count": 0,
                    "report_saved": save_report and self.storage_service is not None
                }
            
            found_matches = []
            safe_packages = []
            
            # Get registry name for dynamic field naming
            registry_name = self.registry_service.get_registry_name()
            match_builder = RegistryPackageMatchBuilder(registry_name)
            
            for malicious_pkg in malicious_packages:
                try:
                    # Search for this package in the registry
                    registry_results = await self.registry_service.search_packages(malicious_pkg.name, ecosystem)
                    
                    if registry_results:
                        # Check if any versions match
                        registry_versions = [result.get('version', '') for result in registry_results if result.get('version')]
                        malicious_versions = malicious_pkg.affected_versions if hasattr(malicious_pkg, 'affected_versions') else [malicious_pkg.version] if malicious_pkg.version else []
                        
                        # Check for version matches
                        version_matches = []
                        for registry_version in registry_versions:
                            if registry_version and registry_version in malicious_versions:
                                version_matches.append(registry_version)
                        
                        # Create registry package match
                        package_match = match_builder.build_match(
                            package=malicious_pkg,
                            registry_results=registry_results,
                            matching_versions=version_matches,
                            all_registry_versions=registry_versions,
                            malicious_versions=malicious_versions
                        )
                        
                        if version_matches:
                            found_matches.append(package_match.to_match_dict())
                            self.logger.warning(f"Critical match found: {malicious_pkg.name} versions {version_matches}")
                        else:
                            safe_packages.append(package_match.to_safe_dict())
                    
                except Exception as e:
                    self.logger.error(f"Error checking package {malicious_pkg.name}: {e}")
                    errors.append({
                        'package': malicious_pkg.name,
                        'error': str(e)
                    })
            
            # Clean up registry connection
            await self.registry_service.close()
            
            not_found_count = len(malicious_packages) - len(found_matches) - len(safe_packages) - len(errors)
            
            # Determine scan status
            status = ScanStatus.SUCCESS
            if errors and len(errors) >= len(malicious_packages):
                status = ScanStatus.FAILED
            elif errors:
                status = ScanStatus.PARTIAL
            
            # Extract packages that were found in the registry (both matches and safe packages)
            found_malicious_packages = []
            for match in found_matches:
                found_malicious_packages.append(match['package'])
            for safe in safe_packages:
                found_malicious_packages.append(safe['package'])
            
            # Save scan result if storage is available and save_report is True
            report_saved = False
            if save_report and self.storage_service:
                try:
                    await self._save_scan_result(
                        scan_id, start_time, status, len(malicious_packages), 
                        malicious_packages, [], found_malicious_packages, errors
                    )
                    report_saved = True
                    self.logger.debug(f"Scan result saved to storage (scan_id: {scan_id})")
                except Exception as e:
                    self.logger.error(f"Failed to save scan result: {e}")
                    errors.append(f"Failed to save scan result: {e}")
            
            result = {
                "success": True,
                "scan_id": scan_id,
                "total_osv_packages": len(malicious_packages),
                "filtered_packages": len(malicious_packages),
                "found_matches": found_matches,
                "safe_packages": safe_packages,
                "errors": errors,
                "not_found_count": not_found_count,
                "report_saved": report_saved
            }
            
            self.logger.info(f"Cross-reference analysis complete: {len(found_matches)} critical matches, {len(safe_packages)} safe packages, {not_found_count} not found, {len(errors)} errors")
            
            # Send notifications if enabled and there are critical matches
            notification_sent = False
            if send_notifications and self.notification_service and found_matches:
                try:
                    notification_sent = await self._send_critical_notification(
                        scan_id, start_time, status, len(malicious_packages),
                        malicious_packages, found_malicious_packages, errors
                    )
                    result["notification_sent"] = notification_sent
                except Exception as e:
                    self.logger.error(f"Failed to send notification: {e}")
                    result["notification_error"] = str(e)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during security cross-reference analysis: {e}")
            # Clean up registry connection on error
            if self.registry_service:
                try:
                    await self.registry_service.close()
                except Exception:
                    pass
            
            return {
                "success": False,
                "error": str(e),
                "total_osv_packages": 0,
                "filtered_packages": 0,
                "found_matches": [],
                "safe_packages": [],
                "errors": [],
                "not_found_count": 0
            }
    
    async def crossref_analysis_with_blocking(
        self, 
        hours: int = 6, 
        ecosystem: str = "npm", 
        limit: Optional[int] = None,
        save_report: bool = True,
        block_packages: bool = False,
        send_notifications: bool = True,
        progress_callback: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Cross-reference OSV malicious packages with JFrog registry, with optional proactive blocking.
        
        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (default: npm)
            limit: Maximum number of malicious packages to check
            save_report: Whether to save the scan result to storage (default: True)
            block_packages: Whether to block malicious packages before analysis (default: False)
            send_notifications: Whether to send notifications for critical matches (default: True)
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary containing analysis results including blocking information
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        errors = []
        blocking_result = None
        
        try:
            self.logger.debug(f"Starting enhanced security cross-reference analysis for {ecosystem} packages from last {hours} hours (scan_id: {scan_id}, blocking={block_packages})")
            
            # Step 1: Optional proactive blocking
            if block_packages:
                try:
                    if progress_callback:
                        progress_callback("Proactively blocking malicious packages...", 0, 100)
                    
                    from .proactive_security import ProactiveSecurityUseCase
                    proactive_usecase = ProactiveSecurityUseCase(
                        packages_feed=self.packages_feed,
                        registry_service=self.registry_service
                    )
                    
                    def blocking_progress(message, current, total):
                        if progress_callback:
                            # Scale progress to 0-40% range for blocking phase
                            scaled_progress = int((current / total) * 40)
                            progress_callback(f"Blocking: {message}", scaled_progress, 100)
                    
                    blocking_result = await proactive_usecase.block_recent_malicious_packages(
                        hours=hours,
                        ecosystem=ecosystem,
                        limit=limit,
                        progress_callback=blocking_progress
                    )
                    
                    if not blocking_result["success"]:
                        self.logger.warning(f"Proactive blocking failed: {blocking_result.get('error', 'Unknown error')}")
                        errors.append(f"Proactive blocking failed: {blocking_result.get('error', 'Unknown error')}")
                    else:
                        self.logger.debug(f"Proactive blocking complete: {blocking_result['success_count']} packages blocked")
                        
                except Exception as e:
                    self.logger.error(f"Error during proactive blocking: {e}")
                    errors.append(f"Proactive blocking error: {str(e)}")
            
            # Step 2: Regular cross-reference analysis
            if progress_callback:
                progress_callback("Running cross-reference analysis...", 50 if block_packages else 0, 100)
            
            analysis_result = await self.crossref_analysis(hours, ecosystem, limit, save_report, send_notifications)
            
            if progress_callback:
                progress_callback("Analysis complete", 100, 100)
            
            # Combine results
            combined_result = analysis_result.copy()
            if blocking_result:
                combined_result["blocking_result"] = blocking_result
                combined_result["packages_blocked"] = blocking_result.get("blocked_packages", [])
                combined_result["blocking_errors"] = blocking_result.get("errors", [])
                # Add blocking errors to main errors list
                combined_result["errors"].extend(errors)
            else:
                combined_result["blocking_result"] = None
                combined_result["packages_blocked"] = []
                combined_result["blocking_errors"] = []
            
            return combined_result
            
        except Exception as e:
            self.logger.error(f"Error during enhanced security cross-reference analysis: {e}")
            # Clean up registry connection on error
            if self.registry_service:
                try:
                    await self.registry_service.close()
                except Exception:
                    pass
            
            return {
                "success": False,
                "error": str(e),
                "total_osv_packages": 0,
                "filtered_packages": 0,
                "found_matches": [],
                "safe_packages": [],
                "errors": errors + [str(e)],
                "not_found_count": 0,
                "blocking_result": blocking_result,
                "packages_blocked": blocking_result.get("blocked_packages", []) if blocking_result else [],
                "blocking_errors": blocking_result.get("errors", []) if blocking_result else []
            }
    
    async def _save_scan_result(
        self,
        scan_id: str,
        start_time: datetime,
        status: ScanStatus,
        packages_scanned: int,
        malicious_packages_found: List[MaliciousPackage],
        packages_blocked: List[str],
        packages_already_present: List[MaliciousPackage],
        errors: List[str]
    ) -> None:
        """
        Save scan result to storage.
        
        Args:
            scan_id: Unique identifier for the scan
            start_time: When the scan started
            status: Status of the scan
            packages_scanned: Number of packages scanned
            malicious_packages_found: List of all malicious packages from OSV feed (for reference)
            packages_blocked: List of package names that were blocked
            packages_already_present: List of packages found in the JFrog registry (findings)
            errors: List of error messages
        """
        if not self.storage_service:
            return
        
        end_time = datetime.now(timezone.utc)
        execution_duration = (end_time - start_time).total_seconds()
        
        scan_result = ScanResult(
            scan_id=scan_id,
            timestamp=start_time,
            status=status,
            packages_scanned=packages_scanned,
            malicious_packages_found=malicious_packages_found,
            packages_blocked=packages_blocked,
            malicious_packages_list=packages_already_present,
            errors=[str(error) if isinstance(error, dict) else error for error in errors],
            execution_duration_seconds=execution_duration
        )
        
        await self.storage_service.store_scan_result(scan_result, self.registry_service)
    
    async def _send_critical_notification(
        self,
        scan_id: str,
        start_time: datetime,
        status: ScanStatus,
        packages_scanned: int,
        all_malicious_packages: List[MaliciousPackage],
        packages_found_in_registry: List[MaliciousPackage],
        errors: List[str]
    ) -> bool:
        """
        Send notification for critical security findings.
        
        Args:
            scan_id: Unique identifier for the scan
            start_time: When the scan started
            status: Status of the scan
            packages_scanned: Number of packages scanned
            all_malicious_packages: List of all malicious packages from OSV feed
            packages_found_in_registry: List of packages found in the registry (critical findings)
            errors: List of error messages
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.notification_service or not packages_found_in_registry:
            return False
        
        try:
            end_time = datetime.now(timezone.utc)
            execution_duration = (end_time - start_time).total_seconds()
            
            # Create a ScanResult for the notification
            scan_result = ScanResult(
                scan_id=scan_id,
                timestamp=start_time,
                status=status,
                packages_scanned=packages_scanned,
                malicious_packages_found=all_malicious_packages,
                packages_blocked=[],  # No blocking in this analysis
                malicious_packages_list=packages_found_in_registry,  # These are the critical findings
                errors=[str(error) if isinstance(error, dict) else error for error in errors],
                execution_duration_seconds=execution_duration
            )
            
            # Create notification event
            event = NotificationEvent.create_threat_notification(
                event_id=f"threat-{scan_id}",
                scan_result=scan_result,
                channels=[NotificationChannel.WEBHOOK],  # MS Teams uses webhook
                metadata={
                    "registry": self.registry_service.get_registry_name(),
                    "scan_type": "crossref_analysis",
                    "critical_packages_count": len(packages_found_in_registry)
                }
            )
            
            # Add registry information to the notification event
            # Since NotificationEvent is frozen, we need to create a new one with registry info
            event_with_registry = NotificationEvent(
                event_id=event.event_id,
                timestamp=event.timestamp,
                level=event.level,
                title=event.title,
                message=event.message,
                scan_result=event.scan_result,
                affected_packages=event.affected_packages,
                channels=event.channels,
                metadata=event.metadata,
                registry_type=getattr(self.registry_service, 'registry_type', 'unknown'),
                registry_url=getattr(self.registry_service, 'base_url', None)
            )
            
            # Send notification
            success = await self.notification_service.send_notification(event_with_registry)
            
            if success:
                self.logger.info(f"Successfully sent critical security notification for scan {scan_id}")
            else:
                self.logger.warning(f"Failed to send critical security notification for scan {scan_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending critical security notification: {e}")
            return False