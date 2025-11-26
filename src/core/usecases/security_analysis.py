"""Security Analysis Use Case for cross-referencing OSV data with package registry."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..entities.malicious_package import MaliciousPackage
from ..entities.notification_event import NotificationChannel, NotificationEvent
from ..entities.registry_package_match import RegistryPackageMatchBuilder
from ..entities.scan_result import ScanResult, ScanStatus
from ..interfaces.packages_feed import PackagesFeed
from ..interfaces.packages_registry_service import PackagesRegistryService
from ..interfaces.storage_service import StorageService
from ..utils.version_matcher import VersionMatcher
from ..wildcard_compressor import WildcardCompressor


class SecurityAnalysisUseCase:
    """Use case for security analysis operations."""

    def __init__(
        self,
        packages_feed: PackagesFeed,
        registry_service: PackagesRegistryService,
        storage_service: Optional[StorageService] = None,
        notification_service: Optional[Any] = None,
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

    async def crossref_analysis_with_packages(
        self,
        malicious_packages: List[MaliciousPackage],
        save_report: bool = True,
        send_notifications: bool = True,
        progress_callback: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Cross-reference pre-fetched malicious packages with JFrog registry.

        This method is optimized to avoid re-fetching packages that were already retrieved.

        Args:
            malicious_packages: Already-fetched list of malicious packages
            save_report: Whether to save the scan result to storage (default: True)
            send_notifications: Whether to send notifications for critical matches (default: True)
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary containing analysis results
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        errors = []

        try:
            if not malicious_packages:
                self.logger.info("No malicious packages provided for analysis")

                # Save empty scan result if storage is available and save_report is True
                if save_report and self.storage_service:
                    await self._save_scan_result(
                        scan_id,
                        start_time,
                        ScanStatus.SUCCESS,
                        0,
                        [],
                        [],
                        [],
                        errors,
                        [],
                    )

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "ecosystems_scanned": [],
                    "total_osv_packages": 0,
                    "filtered_packages": 0,
                    "found_matches": [],
                    "safe_packages": [],
                    "errors": [],
                    "not_found_count": 0,
                    "report_saved": save_report and self.storage_service is not None,
                }

            # Group packages by ecosystem for reporting
            packages_by_ecosystem = {}
            for pkg in malicious_packages:
                eco = pkg.ecosystem
                if eco not in packages_by_ecosystem:
                    packages_by_ecosystem[eco] = []
                packages_by_ecosystem[eco].append(pkg)

            ecosystems_to_scan = list(packages_by_ecosystem.keys())
            ecosystem_summary = {
                eco: len(pkgs) for eco, pkgs in packages_by_ecosystem.items()
            }
            self.logger.info(
                f"Analyzing {len(malicious_packages)} pre-fetched malicious packages across ecosystems: {ecosystem_summary}"
            )

            # Step 2: Check packages against registry using wildcard compression
            self.logger.debug(
                "Checking packages against registry with wildcard compression"
            )
            registry_name = self.registry_service.get_registry_name()
            match_builder = RegistryPackageMatchBuilder(registry_name=registry_name)

            if progress_callback:
                progress_callback(
                    "Searching registry for malicious packages...", 50, 100
                )

            results = await self._check_packages_with_wildcard_compression(
                malicious_packages, match_builder
            )

            if progress_callback:
                progress_callback("Processing results...", 90, 100)

            # Process results
            found_matches = []
            safe_packages = []
            not_found = []
            timeout_errors = []

            for result in results:
                if result["type"] == "match":
                    found_matches.append(result["data"])
                elif result["type"] == "safe":
                    safe_packages.append(result["data"])
                elif result["type"] == "not_found":
                    not_found.append(result["data"])
                elif result["type"] == "error":
                    error_data = result["data"]
                    if "timeout" in error_data.get("error", "").lower():
                        timeout_errors.append(error_data)
                    else:
                        errors.append(
                            f"{error_data.get('package', 'Unknown')}: {error_data.get('error', 'Unknown error')}"
                        )

            self.logger.info(
                f"Analysis complete: {len(found_matches)} critical matches, "
                f"{len(safe_packages)} safe (different versions), "
                f"{len(not_found)} not found, {len(timeout_errors)} timeouts, "
                f"{len(errors)} errors"
            )

            # Save scan result if storage is available and save_report is True
            report_saved = False
            if save_report and self.storage_service:
                try:
                    # Extract MaliciousPackage objects from match dicts
                    malicious_packages_found = []
                    for match_dict in found_matches:
                        if isinstance(match_dict, dict) and "package" in match_dict:
                            malicious_packages_found.append(match_dict["package"])
                        elif hasattr(match_dict, "package"):
                            malicious_packages_found.append(match_dict.package)

                    # Extract MaliciousPackage objects from safe package dicts
                    safe_packages_found = []
                    for safe_dict in safe_packages:
                        if isinstance(safe_dict, dict) and "package" in safe_dict:
                            safe_packages_found.append(safe_dict["package"])
                        elif hasattr(safe_dict, "package"):
                            safe_packages_found.append(safe_dict.package)

                    # Extract MaliciousPackage objects from not_found dicts
                    not_found_packages = []
                    for not_found_dict in not_found:
                        if (
                            isinstance(not_found_dict, dict)
                            and "package" in not_found_dict
                        ):
                            not_found_packages.append(not_found_dict["package"])
                        elif hasattr(not_found_dict, "package"):
                            not_found_packages.append(not_found_dict.package)

                    await self._save_scan_result(
                        scan_id,
                        start_time,
                        ScanStatus.SUCCESS,
                        len(malicious_packages),
                        malicious_packages_found,  # Only found matches (MaliciousPackage objects)
                        [],  # No packages blocked in this analysis
                        malicious_packages_found,  # These are the findings (packages found in registry)
                        errors,
                        ecosystems_to_scan,
                    )
                    report_saved = True
                except Exception as e:
                    self.logger.error(f"Error saving scan result: {e}")
                    errors.append(f"Failed to save scan result: {str(e)}")

            # Send notifications if enabled and there are critical matches
            if send_notifications and found_matches and self.notification_service:
                try:
                    # Extract MaliciousPackage objects from found_matches
                    malicious_packages_in_registry = [
                        match["package"] for match in found_matches
                    ]

                    await self._send_critical_notification(
                        scan_id=scan_id,
                        start_time=start_time,
                        status=ScanStatus.SUCCESS,
                        packages_scanned=len(malicious_packages),
                        all_malicious_packages=malicious_packages,
                        packages_found_in_registry=malicious_packages_in_registry,
                        errors=errors,
                    )
                except Exception as e:
                    self.logger.error(f"Error sending notifications: {e}")
                    errors.append(f"Failed to send notifications: {str(e)}")

            return {
                "success": True,
                "scan_id": scan_id,
                "ecosystems_scanned": ecosystems_to_scan,
                "total_osv_packages": len(malicious_packages),
                "filtered_packages": len(malicious_packages),
                "found_matches": found_matches,
                "safe_packages": safe_packages,
                "not_found": not_found,
                "timeout_errors": timeout_errors,
                "errors": errors,
                "not_found_count": len(not_found),
                "report_saved": report_saved,
            }

        except Exception as e:
            self.logger.error(f"Error during security cross-reference analysis: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_osv_packages": 0,
                "filtered_packages": 0,
                "found_matches": [],
                "safe_packages": [],
                "not_found": [],
                "timeout_errors": [],
                "errors": [str(e)],
                "not_found_count": 0,
                "report_saved": False,
            }

        finally:
            # Always clean up registry connection
            if self.registry_service:
                try:
                    await self.registry_service.close()
                except Exception as cleanup_error:
                    self.logger.debug(
                        f"Non-critical error during cleanup: {cleanup_error}"
                    )

    async def crossref_analysis(
        self,
        hours: int = 6,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None,
        save_report: bool = True,
        send_notifications: bool = True,
    ) -> Dict[str, Any]:
        """
        Cross-reference OSV malicious packages with JFrog registry.

        Args:
            hours: Hours ago to look for recent malicious packages
            ecosystem: Package ecosystem to filter (None for all available ecosystems)
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
            # Determine which ecosystems to scan
            if ecosystem:
                ecosystems_to_scan = [ecosystem]
                self.logger.debug(
                    f"Starting security cross-reference analysis for {ecosystem} packages from last {hours} hours (scan_id: {scan_id})"
                )
            else:
                # Get all available ecosystems from OSV
                all_osv_ecosystems = await self.packages_feed.get_available_ecosystems()

                # Get supported ecosystems from registry
                if hasattr(self.registry_service, "get_supported_ecosystems"):
                    registry_ecosystems = (
                        await self.registry_service.get_supported_ecosystems()
                    )
                    # Only scan ecosystems that both OSV and registry support
                    ecosystems_to_scan = [
                        eco for eco in all_osv_ecosystems if eco in registry_ecosystems
                    ]
                else:
                    # Fallback to all OSV ecosystems if registry doesn't support discovery
                    ecosystems_to_scan = all_osv_ecosystems

                self.logger.info(
                    f"Starting multi-ecosystem security scan for {len(ecosystems_to_scan)} ecosystems: {ecosystems_to_scan}"
                )

            # Step 1: Fetch recent malicious packages from OSV for specified ecosystems
            malicious_packages = await self.packages_feed.fetch_malicious_packages(
                max_packages=limit, hours=hours, ecosystems=ecosystems_to_scan
            )

            if not malicious_packages:
                self.logger.info(
                    f"No malicious packages found in the last {hours} hours for ecosystems: {ecosystems_to_scan}"
                )

                # Save empty scan result if storage is available and save_report is True
                if save_report and self.storage_service:
                    await self._save_scan_result(
                        scan_id,
                        start_time,
                        ScanStatus.SUCCESS,
                        0,
                        [],
                        [],
                        [],
                        errors,
                        ecosystems_to_scan,
                    )

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "ecosystems_scanned": ecosystems_to_scan,
                    "total_osv_packages": 0,
                    "filtered_packages": 0,
                    "found_matches": [],
                    "safe_packages": [],
                    "errors": [],
                    "not_found_count": 0,
                    "report_saved": save_report and self.storage_service is not None,
                }

            # Group packages by ecosystem for reporting
            packages_by_ecosystem = {}
            for pkg in malicious_packages:
                eco = pkg.ecosystem
                if eco not in packages_by_ecosystem:
                    packages_by_ecosystem[eco] = []
                packages_by_ecosystem[eco].append(pkg)

            ecosystem_summary = {
                eco: len(pkgs) for eco, pkgs in packages_by_ecosystem.items()
            }
            self.logger.info(
                f"Found {len(malicious_packages)} malicious packages across ecosystems: {ecosystem_summary}"
            )

            self.logger.debug(
                f"Found {len(malicious_packages)} malicious packages to check"
            )

            # Step 2: Check each malicious package against JFrog

            # Check JFrog health first
            if not await self.registry_service.health_check():
                self.logger.error("JFrog registry is not accessible")
                error_msg = "JFrog registry is not accessible"
                errors.append(error_msg)

                # Save failed scan result if storage is available and save_report is True
                if save_report and self.storage_service:
                    await self._save_scan_result(
                        scan_id,
                        start_time,
                        ScanStatus.FAILED,
                        len(malicious_packages),
                        malicious_packages,
                        [],
                        [],
                        errors,
                        ecosystems_to_scan,
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
                    "report_saved": save_report and self.storage_service is not None,
                }

            found_matches = []
            safe_packages = []
            errors = []

            # Get registry name for dynamic field naming
            registry_name = self.registry_service.get_registry_name()
            match_builder = RegistryPackageMatchBuilder(registry_name)

            # Process packages with wildcard compression for efficiency
            self.logger.info(
                f"Processing {len(malicious_packages)} packages against registry with wildcard compression"
            )
            results = await self._check_packages_with_wildcard_compression(
                malicious_packages, match_builder, max_concurrent=10
            )

            # Separate results into found_matches, safe_packages, and errors
            for result in results:
                if result["type"] == "match":
                    found_matches.append(result["data"])
                elif result["type"] == "safe":
                    safe_packages.append(result["data"])
                elif result["type"] == "error":
                    errors.append(result["data"])

            # Clean up registry connection
            await self.registry_service.close()

            not_found_count = (
                len(malicious_packages)
                - len(found_matches)
                - len(safe_packages)
                - len(errors)
            )

            # Determine scan status
            status = ScanStatus.SUCCESS
            if errors and len(errors) >= len(malicious_packages):
                status = ScanStatus.FAILED
            elif errors:
                status = ScanStatus.PARTIAL

            # Extract packages that were found in the registry (both matches and safe packages)
            found_malicious_packages = []
            for match in found_matches:
                found_malicious_packages.append(match["package"])
            for safe in safe_packages:
                found_malicious_packages.append(safe["package"])

            # Save scan result if storage is available and save_report is True
            report_saved = False
            if save_report and self.storage_service:
                try:
                    await self._save_scan_result(
                        scan_id,
                        start_time,
                        status,
                        len(malicious_packages),
                        malicious_packages,
                        [],
                        found_malicious_packages,
                        errors,
                        ecosystems_to_scan,
                    )
                    report_saved = True
                    self.logger.debug(
                        f"Scan result saved to storage (scan_id: {scan_id})"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to save scan result: {e}")
                    errors.append(f"Failed to save scan result: {e}")

            result = {
                "success": True,
                "scan_id": scan_id,
                "ecosystems_scanned": ecosystems_to_scan,
                "total_osv_packages": len(malicious_packages),
                "filtered_packages": len(malicious_packages),
                "found_matches": found_matches,
                "safe_packages": safe_packages,
                "errors": errors,
                "not_found_count": not_found_count,
                "report_saved": report_saved,
            }

            self.logger.info(
                f"Cross-reference analysis complete: {len(found_matches)} critical matches, {len(safe_packages)} safe packages, {not_found_count} not found, {len(errors)} errors"
            )

            # Send notifications if enabled and there are critical matches
            notification_sent = False
            if send_notifications and self.notification_service and found_matches:
                try:
                    notification_sent = await self._send_critical_notification(
                        scan_id,
                        start_time,
                        status,
                        len(malicious_packages),
                        malicious_packages,
                        found_malicious_packages,
                        errors,
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
                except Exception as cleanup_error:
                    self.logger.debug(
                        f"Non-critical error during cleanup: {cleanup_error}"
                    )

            return {
                "success": False,
                "error": str(e),
                "total_osv_packages": 0,
                "filtered_packages": 0,
                "found_matches": [],
                "safe_packages": [],
                "errors": [],
                "not_found_count": 0,
            }

    async def crossref_analysis_with_blocking(
        self,
        hours: int = 6,
        ecosystem: str = "npm",
        limit: Optional[int] = None,
        save_report: bool = True,
        block_packages: bool = False,
        send_notifications: bool = True,
        progress_callback: Optional[Any] = None,
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
        errors = []
        blocking_result = None

        try:
            self.logger.debug(
                f"Starting enhanced security cross-reference analysis for {ecosystem} packages from last {hours} hours (scan_id: {scan_id}, blocking={block_packages})"
            )

            # Step 1: Optional proactive blocking
            if block_packages:
                try:
                    if progress_callback:
                        progress_callback(
                            "Proactively blocking malicious packages...", 0, 100
                        )

                    from .proactive_security import ProactiveSecurityUseCase

                    proactive_usecase = ProactiveSecurityUseCase(
                        packages_feed=self.packages_feed,
                        registry_service=self.registry_service,
                    )

                    def blocking_progress(message, current, total):
                        if progress_callback:
                            # Scale progress to 0-40% range for blocking phase
                            scaled_progress = int((current / total) * 40)
                            progress_callback(
                                f"Blocking: {message}", scaled_progress, 100
                            )

                    blocking_result = (
                        await proactive_usecase.block_recent_malicious_packages(
                            hours=hours,
                            ecosystem=ecosystem,
                            limit=limit,
                            progress_callback=blocking_progress,
                        )
                    )

                    if not blocking_result["success"]:
                        self.logger.warning(
                            f"Proactive blocking failed: {blocking_result.get('error', 'Unknown error')}"
                        )
                        errors.append(
                            f"Proactive blocking failed: {blocking_result.get('error', 'Unknown error')}"
                        )
                    else:
                        self.logger.debug(
                            f"Proactive blocking complete: {blocking_result['success_count']} packages blocked"
                        )

                except Exception as e:
                    self.logger.error(f"Error during proactive blocking: {e}")
                    errors.append(f"Proactive blocking error: {str(e)}")

            # Step 2: Regular cross-reference analysis
            # First fetch packages from OSV feed
            if progress_callback:
                progress_callback(
                    "Fetching malicious packages from OSV feed...",
                    50 if block_packages else 0,
                    100,
                )

            malicious_packages = await self.packages_feed.fetch_malicious_packages(
                hours=hours,
                ecosystem=ecosystem if ecosystem else None,
                limit=limit if limit else None,
            )

            if progress_callback:
                progress_callback(
                    "Running cross-reference analysis...",
                    60 if block_packages else 10,
                    100,
                )

            # Pass pre-fetched packages to avoid refetching
            analysis_result = await self.crossref_analysis_with_packages(
                malicious_packages=malicious_packages,
                save_report=save_report,
                send_notifications=send_notifications,
            )

            if progress_callback:
                progress_callback("Analysis complete", 100, 100)

            # Combine results
            combined_result = analysis_result.copy()
            if blocking_result:
                combined_result["blocking_result"] = blocking_result
                combined_result["packages_blocked"] = blocking_result.get(
                    "blocked_packages", []
                )
                combined_result["blocking_errors"] = blocking_result.get("errors", [])
                # Add blocking errors to main errors list
                combined_result["errors"].extend(errors)
            else:
                combined_result["blocking_result"] = None
                combined_result["packages_blocked"] = []
                combined_result["blocking_errors"] = []

            return combined_result

        except Exception as e:
            self.logger.error(
                f"Error during enhanced security cross-reference analysis: {e}"
            )
            # Clean up registry connection on error
            if self.registry_service:
                try:
                    await self.registry_service.close()
                except Exception as cleanup_error:
                    self.logger.debug(
                        f"Non-critical error during cleanup: {cleanup_error}"
                    )

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
                "packages_blocked": (
                    blocking_result.get("blocked_packages", [])
                    if blocking_result
                    else []
                ),
                "blocking_errors": (
                    blocking_result.get("errors", []) if blocking_result else []
                ),
            }

    async def _check_packages_with_wildcard_compression(
        self,
        malicious_packages: List[MaliciousPackage],
        match_builder: RegistryPackageMatchBuilder,
        max_concurrent: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Check packages against registry using wildcard compression to minimize API calls.

        Args:
            malicious_packages: List of malicious packages to check
            match_builder: Builder for creating registry package matches
            max_concurrent: Maximum concurrent wildcard queries (default: 10)

        Returns:
            List of result dictionaries with type and data
        """
        # Group packages by ecosystem first
        packages_by_ecosystem = {}
        for pkg in malicious_packages:
            if pkg.ecosystem not in packages_by_ecosystem:
                packages_by_ecosystem[pkg.ecosystem] = []
            packages_by_ecosystem[pkg.ecosystem].append(pkg)

        self.logger.debug(
            f"💡 Grouped {len(malicious_packages)} packages into {len(packages_by_ecosystem)} ecosystems: {list(packages_by_ecosystem.keys())}"
        )

        all_results = []
        compressor = WildcardCompressor(min_group_size=2)

        for ecosystem, packages in packages_by_ecosystem.items():
            self.logger.info(
                f"Processing {len(packages)} packages for {ecosystem} with wildcard compression"
            )

            # Compress packages into wildcard groups
            wildcard_groups, individual_packages = compressor.compress_packages(
                packages
            )

            self.logger.info(
                f"{ecosystem}: Created {len(wildcard_groups)} wildcard groups and {len(individual_packages)} individual packages"
            )

            # Log compression stats
            stats = compressor.get_compression_stats()
            ecosystem_stats = stats.get(ecosystem, stats.get("overall", {}))
            self.logger.info(
                f"{ecosystem}: {ecosystem_stats.get('queries_original', len(packages))} packages → "
                f"{ecosystem_stats.get('queries_compressed', len(packages))} queries "
                f"({ecosystem_stats.get('reduction_percentage', 0):.1f}% reduction, "
                f"{ecosystem_stats.get('compression_ratio', 1):.2f}x compression)"
            )

            # Process wildcard groups in parallel
            semaphore = asyncio.Semaphore(max_concurrent)

            async def process_wildcard_group(
                prefix: str, group_packages: List[MaliciousPackage]
            ):
                """Process a wildcard group using wildcard search to reduce API calls."""
                async with semaphore:
                    self.logger.info(
                        f"🔍 Processing wildcard group '{prefix}*' with {len(group_packages)} packages"
                    )

                    try:
                        # Use wildcard search to get all packages matching the prefix in ONE query
                        ecosystem = group_packages[0].ecosystem
                        self.logger.info(
                            f"🚀 Calling wildcard search for prefix '{prefix}*' in {ecosystem}"
                        )
                        wildcard_results = (
                            await self.registry_service.search_packages_wildcard(
                                prefix, ecosystem
                            )
                        )
                        self.logger.info(
                            f"✅ Wildcard search for '{prefix}*' returned {len(wildcard_results)} results"
                        )

                        # Match results to specific packages in this group
                        group_results = []
                        for pkg in group_packages:
                            # Filter wildcard results for this specific package
                            pkg_results = []
                            for result in wildcard_results:
                                # Check if this result matches the package
                                result_pkg_name = result.get("package_name", "")
                                result_path = result.get("path", "")

                                # For npm: check if path contains the package name
                                if ecosystem.lower() == "npm":
                                    if (
                                        f".npm/{pkg.name}/" in result_path
                                        or result_path.endswith(f".npm/{pkg.name}")
                                    ):
                                        pkg_results.append(result)
                                else:
                                    # For other ecosystems, match by package name
                                    if (
                                        result_pkg_name == pkg.name
                                        or result.get("name") == pkg.name
                                    ):
                                        pkg_results.append(result)

                            # Process the results for this specific package
                            result = await self._process_package_result(
                                pkg, pkg_results, match_builder, ecosystem
                            )
                            group_results.append(result)

                        self.logger.debug(
                            f"Completed wildcard group '{prefix}' with {len(group_results)} results"
                        )
                        return group_results

                    except Exception as e:
                        # Fallback to individual searches if wildcard fails
                        import traceback

                        traceback.print_exc()
                        self.logger.warning(
                            f"⚠️  Wildcard search failed for group '{prefix}': {e}. Falling back to individual searches."
                        )
                        group_results = []
                        for idx, pkg in enumerate(group_packages):
                            try:
                                if (idx + 1) % 10 == 0:
                                    self.logger.debug(
                                        f"  Group '{prefix}': processed {idx + 1}/{len(group_packages)} packages"
                                    )
                                registry_results = (
                                    await self.registry_service.search_packages(
                                        pkg.name, pkg.ecosystem
                                    )
                                )
                                result = await self._process_package_result(
                                    pkg, registry_results, match_builder, ecosystem
                                )
                                group_results.append(result)
                            except Exception as fallback_error:
                                self.logger.error(
                                    f"Error checking package {pkg.name} ({pkg.ecosystem}): {fallback_error}"
                                )
                                group_results.append(
                                    {
                                        "type": "error",
                                        "data": {
                                            "package": pkg.name,
                                            "error": str(fallback_error),
                                        },
                                    }
                                )

                        self.logger.debug(
                            f"Completed wildcard group '{prefix}' with fallback: {len(group_results)} results"
                        )
                        return group_results

            async def process_individual_package(pkg: MaliciousPackage):
                """Process a single package without wildcard."""
                async with semaphore:
                    try:
                        self.logger.debug(f"Processing individual package: {pkg.name}")
                        registry_results = await self.registry_service.search_packages(
                            pkg.name, pkg.ecosystem
                        )
                        return await self._process_package_result(
                            pkg, registry_results, match_builder, ecosystem
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Error checking package {pkg.name} ({pkg.ecosystem}): {e}"
                        )
                        return {
                            "type": "error",
                            "data": {"package": pkg.name, "error": str(e)},
                        }

            # Execute all wildcard groups in parallel
            self.logger.info(
                f"{ecosystem}: Starting parallel processing of {len(wildcard_groups)} groups and {len(individual_packages)} individual packages"
            )
            wildcard_tasks = [
                process_wildcard_group(prefix, group_packages)
                for prefix, group_packages in wildcard_groups
            ]

            # Execute individual packages in parallel
            individual_tasks = [
                process_individual_package(pkg) for pkg in individual_packages
            ]

            self.logger.info(
                f"{ecosystem}: Awaiting completion of {len(wildcard_tasks)} wildcard tasks and {len(individual_tasks)} individual tasks"
            )

            # Wait for all results
            wildcard_results_nested = await asyncio.gather(
                *wildcard_tasks, return_exceptions=False
            )
            self.logger.info(f"{ecosystem}: Completed all wildcard group tasks")

            individual_results = await asyncio.gather(
                *individual_tasks, return_exceptions=False
            )
            self.logger.info(f"{ecosystem}: Completed all individual package tasks")

            # Flatten wildcard results (each task returns a list)
            for result_list in wildcard_results_nested:
                all_results.extend(result_list)

            all_results.extend(individual_results)

            self.logger.info(
                f"{ecosystem}: Collected {len(all_results)} total results so far"
            )

        self.logger.info(f"Completed processing {len(malicious_packages)} packages")
        return all_results

    async def _process_package_result(
        self,
        malicious_pkg: MaliciousPackage,
        registry_results: List[Dict[str, Any]],
        match_builder: RegistryPackageMatchBuilder,
        ecosystem: str,
    ) -> Dict[str, Any]:
        """
        Process registry search results for a single package.

        Args:
            malicious_pkg: The malicious package being checked
            registry_results: Search results from registry
            match_builder: Builder for creating matches
            ecosystem: Package ecosystem

        Returns:
            Result dictionary with type and data
        """
        try:
            repositories_searched = (
                await self.registry_service.discover_repositories_by_ecosystem(
                    ecosystem
                )
            )

            if registry_results:
                # Extract versions from registry results and deduplicate
                # (same version can appear in multiple repositories)
                registry_versions = list(
                    set(
                        [
                            result.get("version", "")
                            for result in registry_results
                            if result.get("version")
                        ]
                    )
                )
                malicious_versions = (
                    malicious_pkg.affected_versions
                    if hasattr(malicious_pkg, "affected_versions")
                    else ([malicious_pkg.version] if malicious_pkg.version else [])
                )

                # Use unified version matcher
                matching_versions = VersionMatcher.get_matching_versions(
                    registry_versions, malicious_versions
                )

                # Create registry package match
                package_match = match_builder.build_match(
                    package=malicious_pkg,
                    registry_results=registry_results,
                    matching_versions=matching_versions,
                    all_registry_versions=registry_versions,
                    malicious_versions=malicious_versions,
                    repositories_searched=repositories_searched,
                )

                if matching_versions:
                    return {"type": "match", "data": package_match.to_match_dict()}
                else:
                    return {"type": "safe", "data": package_match.to_safe_dict()}
            else:
                # Package not found in registry
                return {
                    "type": "not_found",
                    "data": {
                        "package": malicious_pkg,
                        "repositories": repositories_searched,
                    },
                }

        except Exception as e:
            self.logger.error(
                f"Error checking package {malicious_pkg.name} ({malicious_pkg.ecosystem}): {e}"
            )
            return {
                "type": "error",
                "data": {"package": malicious_pkg.name, "error": str(e)},
            }

    async def _check_packages_parallel(
        self,
        malicious_packages: List[MaliciousPackage],
        match_builder: RegistryPackageMatchBuilder,
        max_concurrent: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Check multiple packages against registry in parallel.

        Args:
            malicious_packages: List of malicious packages to check
            match_builder: Builder for creating registry package matches
            max_concurrent: Maximum concurrent registry requests (default: 10)

        Returns:
            List of result dictionaries with type and data
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        total = len(malicious_packages)

        async def check_single_package(
            idx: int, malicious_pkg: MaliciousPackage
        ) -> Dict[str, Any]:
            """Check a single package with semaphore control."""
            async with semaphore:
                try:
                    if (idx + 1) % 50 == 0 or idx == 0:
                        self.logger.info(
                            f"Progress: {idx + 1}/{total} packages checked"
                        )

                    # Get repositories for this ecosystem
                    repositories_searched = (
                        await self.registry_service.discover_repositories_by_ecosystem(
                            malicious_pkg.ecosystem
                        )
                    )

                    # Search for this package in the registry
                    registry_results = await self.registry_service.search_packages(
                        malicious_pkg.name, malicious_pkg.ecosystem
                    )

                    if registry_results:
                        # Extract versions from registry results
                        registry_versions = [
                            result.get("version", "")
                            for result in registry_results
                            if result.get("version")
                        ]
                        malicious_versions = (
                            malicious_pkg.affected_versions
                            if hasattr(malicious_pkg, "affected_versions")
                            else (
                                [malicious_pkg.version] if malicious_pkg.version else []
                            )
                        )

                        # Use unified version matcher
                        matching_versions = VersionMatcher.get_matching_versions(
                            registry_versions, malicious_versions
                        )

                        # Create registry package match
                        package_match = match_builder.build_match(
                            package=malicious_pkg,
                            registry_results=registry_results,
                            matching_versions=matching_versions,
                            all_registry_versions=registry_versions,
                            malicious_versions=malicious_versions,
                            repositories_searched=repositories_searched,
                        )

                        # Determine if critical match or safe
                        if VersionMatcher.is_critical_match(
                            registry_versions, malicious_versions
                        ):
                            return {
                                "type": "match",
                                "data": package_match.to_match_dict(),
                            }
                        else:
                            return {
                                "type": "safe",
                                "data": package_match.to_safe_dict(),
                            }
                    else:
                        # Package not found
                        return {"type": "not_found", "data": None}

                except Exception as e:
                    self.logger.error(
                        f"Error checking package {malicious_pkg.name} ({malicious_pkg.ecosystem}): {e}"
                    )
                    return {
                        "type": "error",
                        "data": {
                            "package": malicious_pkg.name,
                            "ecosystem": malicious_pkg.ecosystem,
                            "error": str(e),
                        },
                    }

        # Check all packages in parallel
        self.logger.info(
            f"Checking {total} packages with max {max_concurrent} concurrent requests"
        )
        results = await asyncio.gather(
            *[check_single_package(i, pkg) for i, pkg in enumerate(malicious_packages)],
            return_exceptions=False,
        )

        self.logger.info(f"Completed checking {total} packages")
        return results

    async def _save_scan_result(
        self,
        scan_id: str,
        start_time: datetime,
        status: ScanStatus,
        packages_scanned: int,
        malicious_packages_found: List[MaliciousPackage],
        packages_blocked: List[str],
        packages_already_present: List[MaliciousPackage],
        errors: List[str],
        ecosystems_scanned: Optional[List[str]] = None,
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
            ecosystems_scanned: List of ecosystems that were scanned (optional)
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
            errors=[
                str(error) if isinstance(error, dict) else error for error in errors
            ],
            execution_duration_seconds=execution_duration,
            ecosystems_scanned=ecosystems_scanned,
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
        errors: List[str],
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
                errors=[
                    str(error) if isinstance(error, dict) else error for error in errors
                ],
                execution_duration_seconds=execution_duration,
            )

            # Create notification event
            event = NotificationEvent.create_threat_notification(
                event_id=f"threat-{scan_id}",
                scan_result=scan_result,
                channels=[NotificationChannel.WEBHOOK],  # MS Teams uses webhook
                metadata={
                    "registry": self.registry_service.get_registry_name(),
                    "scan_type": "crossref_analysis",
                    "critical_packages_count": len(packages_found_in_registry),
                },
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
                registry_type=getattr(
                    self.registry_service, "registry_type", "unknown"
                ),
                registry_url=getattr(self.registry_service, "base_url", None),
            )

            # Send notification
            success = await self.notification_service.send_notification(
                event_with_registry
            )

            if success:
                self.logger.info(
                    f"Successfully sent critical security notification for scan {scan_id}"
                )
            else:
                self.logger.warning(
                    f"Failed to send critical security notification for scan {scan_id}"
                )

            return success

        except Exception as e:
            self.logger.error(f"Error sending critical security notification: {e}")
            return False
