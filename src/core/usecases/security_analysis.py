"""Security Analysis Use Case for cross-referencing OSV data with JFrog registry."""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
import logging

from ..entities.malicious_package import MaliciousPackage
from ..entities.scan_result import ScanResult, ScanStatus
from ..interfaces.packages_feed import PackagesFeed
from ..interfaces.packages_registry_service import PackagesRegistryService
from ..interfaces.storage_service import StorageService


class SecurityAnalysisUseCase:
    """Use case for security analysis operations."""
    
    def __init__(
        self,
        packages_feed: PackagesFeed,
        registry_service: PackagesRegistryService,
        storage_service: Optional[StorageService] = None
    ):
        """
        Initialize the security analysis use case.
        
        Args:
            packages_feed: Service for fetching malicious package data
            registry_service: Service for interacting with package registry
            storage_service: Service for storing scan results (optional)
        """
        self.packages_feed = packages_feed
        self.registry_service = registry_service
        self.storage_service = storage_service
        self.logger = logging.getLogger(__name__)
    
    async def crossref_analysis(
        self, 
        hours: int = 6, 
        ecosystem: str = "npm", 
        limit: Optional[int] = None,
        save_report: bool = True
    ) -> Dict[str, Any]:
        """
        Cross-reference OSV malicious packages with JFrog registry.
        
        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem (default: npm)
            limit: Maximum number of malicious packages to check
            save_report: Whether to save the scan result to storage (default: True)
            
        Returns:
            Dictionary containing analysis results
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        errors = []
        
        try:
            self.logger.info(f"Starting security cross-reference analysis for {ecosystem} packages from last {hours} hours (scan_id: {scan_id})")
            
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
            
            self.logger.info(f"Found {len(malicious_packages)} malicious {ecosystem} packages to check")
            
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
            
            for malicious_pkg in malicious_packages:
                try:
                    # Search for this package in JFrog
                    jfrog_results = await self.registry_service.search_packages(malicious_pkg.name, ecosystem)
                    
                    if jfrog_results:
                        # Check if any versions match
                        jfrog_versions = [result.get('version', '') for result in jfrog_results if result.get('version')]
                        malicious_versions = malicious_pkg.affected_versions if hasattr(malicious_pkg, 'affected_versions') else [malicious_pkg.version] if malicious_pkg.version else []
                        
                        # Check for version matches
                        version_matches = []
                        for jfrog_version in jfrog_versions:
                            if jfrog_version and jfrog_version in malicious_versions:
                                version_matches.append(jfrog_version)
                        
                        if version_matches:
                            found_matches.append({
                                'package': malicious_pkg,
                                'jfrog_results': jfrog_results,
                                'matching_versions': version_matches,
                                'all_jfrog_versions': jfrog_versions,
                                'malicious_versions': malicious_versions
                            })
                            self.logger.warning(f"Critical match found: {malicious_pkg.name} versions {version_matches}")
                        else:
                            safe_packages.append({
                                'package': malicious_pkg,
                                'jfrog_results': jfrog_results,
                                'jfrog_versions': jfrog_versions,
                                'malicious_versions': malicious_versions
                            })
                    
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
                        found_malicious_packages, [], malicious_packages, errors
                    )
                    report_saved = True
                    self.logger.info(f"Scan result saved to storage (scan_id: {scan_id})")
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
            malicious_packages_found: List of malicious packages found
            packages_blocked: List of package names that were blocked
            packages_already_present: List of packages already present
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
            packages_already_present=packages_already_present,
            errors=[str(error) if isinstance(error, dict) else error for error in errors],
            execution_duration_seconds=execution_duration
        )
        
        await self.storage_service.store_scan_result(scan_result)