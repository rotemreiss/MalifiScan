"""
Scan Results Management Use Case.

This module provides functionality for managing and retrieving scan results,
allowing users             # Analyze the results to get the same format as crossref command
            analysis = await self._analyze_scan_results(scan_result, findings) view recent scans and detailed scan information.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import logging

from ..entities.scan_result import ScanResult
from ..entities.malicious_package import MaliciousPackage
from ..entities.registry_package_match import RegistryPackageMatchBuilder
from ..interfaces.storage_service import StorageService
from ..interfaces.packages_registry_service import PackagesRegistryService


@dataclass
class ScanSummary:
    """Summary information for a scan result."""
    scan_id: str
    timestamp: datetime
    status: str
    packages_scanned: int
    malicious_packages_found: int
    findings_count: int
    execution_duration_seconds: Optional[float] = None


@dataclass
class DetailedScanResult:
    """Detailed scan result with findings and malicious packages."""
    scan_result: ScanResult
    findings: List[MaliciousPackage]
    found_matches: List[Dict[str, Any]]
    safe_packages: List[Dict[str, Any]]
    not_found_count: int


class ScanResultsManager:
    """Use case for managing and retrieving scan results."""
    
    def __init__(self, storage_service: StorageService, registry_service: PackagesRegistryService):
        """
        Initialize the scan results manager.
        
        Args:
            storage_service: Service for retrieving scan data
            registry_service: Service for getting registry information
        """
        self.storage_service = storage_service
        self.registry_service = registry_service
        self.logger = logging.getLogger(__name__)
    
    async def get_recent_scans(self, limit: int = 3) -> List[ScanSummary]:
        """
        Get recent scan summaries sorted by creation date (DESC).
        
        Args:
            limit: Maximum number of scans to return (default: 3)
            
        Returns:
            List of scan summaries
            
        Raises:
            RuntimeError: If storage operation fails
        """
        try:
            self.logger.debug(f"Retrieving {limit} recent scan summaries")
            
            # Get scan results from storage
            scan_results = await self.storage_service.get_scan_results(limit=limit)
            
            if not scan_results:
                self.logger.debug("No scan results found")
                return []
            
            # Convert to scan summaries
            summaries = []
            for scan_result in scan_results:
                # Get findings count for this scan
                findings_count = await self._get_findings_count_for_scan(scan_result.scan_id)
                
                summary = ScanSummary(
                    scan_id=scan_result.scan_id,
                    timestamp=scan_result.timestamp,
                    status=scan_result.status.value,
                    packages_scanned=scan_result.packages_scanned,
                    malicious_packages_found=len(scan_result.malicious_packages_found),
                    findings_count=findings_count,
                    execution_duration_seconds=scan_result.execution_duration_seconds
                )
                summaries.append(summary)
            
            self.logger.debug(f"Retrieved {len(summaries)} scan summaries")
            return summaries
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve recent scans: {e}")
            raise RuntimeError(f"Failed to retrieve recent scans: {e}") from e
    
    async def get_scan_details(self, scan_id: str) -> Optional[DetailedScanResult]:
        """
        Get detailed scan result including findings and analysis.
        
        Args:
            scan_id: Unique identifier of the scan
            
        Returns:
            Detailed scan result or None if not found
            
        Raises:
            RuntimeError: If storage operation fails
        """
        try:
            self.logger.debug(f"Retrieving detailed scan result for scan_id: {scan_id}")
            
            # Get the scan result
            scan_results = await self.storage_service.get_scan_results(scan_id=scan_id)
            
            if not scan_results:
                self.logger.warning(f"No scan result found for scan_id: {scan_id}")
                return None
            
            scan_result = scan_results[0]  # Should be unique by scan_id
            
            # Get findings (packages found in the registry)
            findings = await self._get_findings_for_scan(scan_id)
            
            # Analyze the results to create the same format as crossref command
            analysis = await self._analyze_scan_results(scan_result, findings)
            
            detailed_result = DetailedScanResult(
                scan_result=scan_result,
                findings=findings,
                found_matches=analysis["found_matches"],
                safe_packages=analysis["safe_packages"],
                not_found_count=analysis["not_found_count"]
            )
            
            self.logger.debug(f"Retrieved detailed scan result: {scan_id}")
            return detailed_result
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve scan details for {scan_id}: {e}")
            raise RuntimeError(f"Failed to retrieve scan details: {e}") from e
    
    async def _get_findings_count_for_scan(self, scan_id: str) -> int:
        """Get the count of findings for a specific scan."""
        try:
            # This is a simplified approach - in a real implementation,
            # we'd add a specific method to the storage interface
            findings = await self._get_findings_for_scan(scan_id)
            return len(findings)
        except Exception:
            return 0
    
    async def _get_findings_for_scan(self, scan_id: str) -> List[MaliciousPackage]:
        """Get findings (packages found in registry) for a specific scan."""
        try:
            # Get the scan result first
            scan_results = await self.storage_service.get_scan_results(scan_id=scan_id)
            if not scan_results:
                return []
            
            scan_result = scan_results[0]
            
            # Findings are packages that were found in the registry
            # These are stored in malicious_packages_list (packages_already_present)
            return scan_result.malicious_packages_list
            
        except Exception as e:
            self.logger.error(f"Failed to get findings for scan {scan_id}: {e}")
            return []
    
    async def _analyze_scan_results(self, scan_result: ScanResult, findings: List[MaliciousPackage]) -> Dict[str, Any]:
        """
        Analyze scan results to create the same format as crossref command output.
        
        Args:
            scan_result: The original scan result
            findings: Packages found in the registry
            
        Returns:
            Dictionary with analysis results
        """
        found_matches = []
        safe_packages = []
        
        # Get registry name for dynamic field naming
        registry_name = await self.registry_service.get_registry_name()
        match_builder = RegistryPackageMatchBuilder(registry_name)
        
        # For each finding, create the match information
        for finding in findings:
            # Create registry package match from finding
            package_match = match_builder.build_from_finding(finding)
            
            # Determine if this is a critical match or safe package
            if finding.version and finding.version in (finding.affected_versions or []):
                found_matches.append(package_match.to_match_dict())
            else:
                safe_packages.append(package_match.to_safe_dict())
        
        # Calculate not found count
        total_scanned = len(scan_result.malicious_packages_found)
        found_count = len(findings)
        not_found_count = total_scanned - found_count
        
        return {
            "found_matches": found_matches,
            "safe_packages": safe_packages,
            "not_found_count": not_found_count
        }