#!/usr/bin/env python3
import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.prompt import Confirm
from rich.table import Table

# Import our application components
from src.config.config_loader import Config
from src.core.entities import MaliciousPackage
from src.core.entities.registry_package_match import RegistryPackageMatchBuilder
from src.core.usecases import ConfigurationManagementUseCase
from src.main import SecurityScannerApp  # Import the main app class


class SecurityScannerCLI:
    """CLI interface for the Security Scanner."""

    def __init__(self, config_file: str = "config.yaml", env_file: str = ".env"):
        self.console = Console()
        self.config_file = config_file
        self.env_file = env_file
        self.app: Optional[SecurityScannerApp] = None
        self.config: Optional[Config] = None
        self.services: Dict[str, Any] = {}

    async def initialize(self):
        """Initialize the CLI with configuration and services."""
        try:
            # Configure CLI-specific logging BEFORE app initialization
            # (reduce verbosity for better UX)
            self._configure_cli_logging()

            # Create and initialize the main app
            self.app = SecurityScannerApp(self.config_file, self.env_file)
            await self.app.initialize()

            # Get references for convenience
            self.config = self.app.config
            self.services = {
                "feed": self.app.services["packages_feed"],
                "registry": self.app.services["packages_registry"],
                "notification": self.app.services["notification_service"],
                "storage": self.app.services["storage_service"],
                "scanner": self.app.security_scanner,
            }

            self.console.print("✅ CLI initialized successfully", style="green")

        except Exception as e:
            self.console.print(f"❌ Failed to initialize CLI: {e}", style="red")
            raise

    def _configure_cli_logging(self):
        """Configure CLI logging to reduce verbosity but keep error visibility."""
        # Set most loggers to WARNING level to reduce noise
        verbose_modules = [
            "src.providers.feeds.osv_feed",
            "src.providers.registries.jfrog_registry",
            "src.core.usecases.security_analysis",
            "src.core.usecases.data_management",
            "src.core.usecases.proactive_security",
            "src.factories.service_factory",
            "src.main",
            "asyncio",
            "httpx",
            "httpcore",
        ]

        for module in verbose_modules:
            logger = logging.getLogger(module)
            logger.setLevel(logging.WARNING)

        # Set root logger to WARNING level to suppress most INFO messages
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.WARNING)

        # Add a filter to suppress certain noisy log messages
        class CLILogFilter(logging.Filter):
            def filter(self, record):
                # Suppress common verbose messages but keep important ones
                message = record.getMessage().lower()
                suppress_patterns = [
                    "fetching package",
                    "successfully parsed package",
                    "application initialized",
                    "application initialization complete",
                    "creating services",
                    "creating use cases",
                    "notification service is disabled",
                    "fetching malicious packages from osv",
                    "starting to fetch malicious packages",
                    "filtering packages modified after",
                    "attempting to read",
                    "successfully downloaded csv",
                    "found malicious package",
                    "found malicious packages",
                    "will fetch first",
                    "successfully fetched",
                    "fetched packages from osv feed",
                    "proactive blocking complete",
                    "blocking package",
                    "successfully blocked",
                    "failed to block",
                    "blocking packages in batch",
                ]

                # Check if this is a message we want to suppress
                for pattern in suppress_patterns:
                    if pattern in message:
                        # Suppress INFO and WARNING messages that match our patterns
                        if record.levelno in (logging.INFO, logging.WARNING):
                            return False

                return True

            # Apply filter to all handlers

        for handler in root_logger.handlers:
            handler.addFilter(CLILogFilter())

    async def _get_registry_name(self) -> str:
        """Get the display name of the current registry."""
        try:
            if self.services and "registry" in self.services:
                return self.services[
                    "registry"
                ].get_registry_name()  # Remove await - this is a sync method
            return "Package Registry"  # Fallback
        except Exception:
            return "Package Registry"  # Fallback on error

    async def _get_dynamic_field_names(self) -> Dict[str, str]:
        """Get dynamic field names based on registry type."""
        try:
            registry_name = await self._get_registry_name()
            match_builder = RegistryPackageMatchBuilder(registry_name)
            dummy_match = match_builder.build_match(None)  # Just for field names

            return {
                "all_versions_field": dummy_match.get_all_versions_field_name(),
                "versions_field": dummy_match.get_versions_field_name(),
                "results_field": dummy_match.get_results_field_name(),
            }
        except Exception:
            # Fallback to hardcoded names if something goes wrong
            return {
                "all_versions_field": "all_jfrog_versions",
                "versions_field": "jfrog_versions",
                "results_field": "jfrog_results",
            }

    async def registry_health(self) -> bool:
        """Check package registry health."""
        try:
            self.console.print("🔍 Checking package registry health...")

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            result = await self.app.registry_management.health_check()

            if result["success"] and result["healthy"]:
                self.console.print(
                    f"✅ {result['registry_name']} is healthy and accessible",
                    style="green",
                )
                return True
            else:
                error_msg = result.get("error", "Registry is not accessible")
                self.console.print(
                    f"❌ Registry health check failed: {error_msg}", style="red"
                )
                return False

        except Exception as e:
            self.console.print(
                f"❌ Error checking package registry health: {e}", style="red"
            )
            return False

    async def registry_search(self, package_name: str, ecosystem: str = "npm") -> bool:
        """Search for a package in the package registry."""
        try:
            self.console.print(
                f"🔍 Searching for package: {package_name} ({ecosystem})"
            )

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            search_result = await self.app.registry_management.search_package(
                package_name, ecosystem
            )

            if not search_result["success"]:
                error_msg = search_result.get("error", "Unknown error")
                self.console.print(f"❌ Search failed: {error_msg}", style="red")
                return False

            # Display results using rich formatting
            table = Table(title=f"Package Search Results: {package_name}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="magenta")

            table.add_row("Package Name", search_result["package_name"])
            table.add_row("Ecosystem", search_result["ecosystem"])
            table.add_row(
                "Registry Health",
                "✅ Healthy" if search_result["registry_healthy"] else "❌ Unhealthy",
            )

            # Show repositories searched
            repositories_searched = search_result.get("repositories_searched", [])
            if repositories_searched:
                repos_display = ", ".join(repositories_searched)
                if len(repos_display) > 50:  # Truncate if too long
                    repos_display = repos_display[:47] + "..."
                table.add_row("Repositories Searched", repos_display)
            else:
                table.add_row("Repositories Searched", "None found")

            table.add_row(
                "Search Results", f"{search_result['results_count']} packages found"
            )
            table.add_row(
                "Currently Blocked",
                "🚫 Yes" if search_result["is_blocked"] else "✅ No",
            )

            self.console.print(table)

            # Display detailed search results if any found
            search_results = search_result["search_results"]
            if search_results:
                self.console.print(
                    f"\n📦 Found {len(search_results)} matching packages:"
                )
                results_table = Table()
                results_table.add_column("Name", style="cyan")
                results_table.add_column("Version", style="magenta")
                results_table.add_column("Path", style="white")
                results_table.add_column("Size", style="yellow")
                results_table.add_column("Modified", style="green")

                for result in search_results[:10]:  # Limit to first 10 results
                    size_str = (
                        f"{result.get('size', 0):,} bytes"
                        if result.get("size")
                        else "Unknown"
                    )
                    modified = result.get("modified", "Unknown")[
                        :19
                    ]  # Truncate timestamp
                    version = result.get("version", "Unknown")
                    results_table.add_row(
                        result.get("name", "Unknown"),
                        version,
                        result.get("path", "Unknown"),
                        size_str,
                        modified,
                    )

                self.console.print(results_table)

                if len(search_results) > 10:
                    self.console.print(
                        f"... and {len(search_results) - 10} more results"
                    )

            # Ensure session is properly closed
            registry = self.services.get("registry")
            if registry:
                await registry.close()

            return True

        except Exception as e:
            self.console.print(f"❌ Error searching package: {e}", style="red")
            # Ensure session is properly closed on exception
            registry = self.services.get("registry")
            if registry:
                await registry.close()
            return False

    def _parse_inject_packages(
        self, inject_packages_str: str
    ) -> List["MaliciousPackage"]:
        """
        Parse inject packages string and create MaliciousPackage objects.

        Format: "ecosystem:name:version,ecosystem:name:version"
        Example: "npm:lodash:4.17.21,PyPI:requests:2.28.0"

        Args:
            inject_packages_str: Comma-separated list of packages

        Returns:
            List of MaliciousPackage objects
        """
        from datetime import datetime, timezone

        from src.core.entities import MaliciousPackage

        packages = []
        if not inject_packages_str:
            return packages

        for package_str in inject_packages_str.split(","):
            parts = package_str.strip().split(":")
            if len(parts) != 3:
                self.console.print(
                    f"⚠️  Invalid package format: {package_str} (expected ecosystem:name:version)",
                    style="yellow",
                )
                continue

            ecosystem, name, version = parts

            # Create a test malicious package
            package = MaliciousPackage(
                name=name,
                version=version,
                ecosystem=ecosystem,
                package_url=f"pkg:{ecosystem.lower()}/{name}@{version}",
                advisory_id=f"TEST-INJECT-{name.upper()}",
                summary=f"Test injected package: {name} ({ecosystem})",
                details="This is a test package injected via --inject-packages for demonstration purposes.",
                aliases=[],
                affected_versions=[version],
                database_specific={"injected": True, "test": True},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            )
            packages.append(package)

        return packages

    async def security_crossref(
        self,
        hours: int = 6,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None,
        no_report: bool = False,
        block: bool = False,
        no_notifications: bool = False,
        inject_packages: Optional[str] = None,
    ) -> bool:
        """Cross-reference malicious packages from feed with package registry."""
        try:
            self.console.print(
                "🔍 Security Cross-Reference Analysis", style="bold cyan"
            )
            self.console.print(
                f"📅 Looking for malicious packages from the last {hours} hours"
            )

            if ecosystem:
                self.console.print(f"🏗️ Ecosystem: {ecosystem}")
            else:
                self.console.print(
                    "🏗️ Ecosystems: All available (registry-first optimization)"
                )

            if block:
                self.console.print(
                    "🚫 Block mode: Will proactively block malicious packages",
                    style="bold red",
                )

            if inject_packages:
                self.console.print(
                    "💉 Test mode: Injecting additional packages for testing",
                    style="bold yellow",
                )

            self.console.print()

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            # Step 1: Get malicious packages from feed
            self.console.print(
                "Step 1: Fetching malicious packages from the Malicious packages feed...",
                style="yellow",
            )

            malicious_packages = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=False,
            ) as progress:
                fetch_task = progress.add_task(
                    "Fetching malicious package IDs and gathering detailed information...",
                    total=None,
                )

                # Fetch packages from the feed
                fetch_result = await self.app.fetch_packages_feed_data(
                    ecosystem, limit, hours
                )

                if not fetch_result["success"]:
                    progress.update(fetch_task, description="❌ Feed fetch failed")
                    if fetch_result.get("error"):
                        self.console.print(
                            f"❌ Error: {fetch_result['error']}", style="red"
                        )
                    return False

                progress.update(fetch_task, description="✅ Feed fetch complete")
                malicious_packages = fetch_result["packages"]

            # Inject additional test packages if specified
            if inject_packages:
                injected = self._parse_inject_packages(inject_packages)
                if injected:
                    malicious_packages.extend(injected)
                    self.console.print(
                        f"💉 Injected {len(injected)} test packages", style="yellow"
                    )

            if not malicious_packages:
                ecosystem_desc = (
                    ecosystem if ecosystem else "packages across all ecosystems"
                )
                self.console.print(
                    f"✅ No malicious {ecosystem_desc} found in the last {hours} hours",
                    style="green",
                )
                return True

            # Create ecosystem description for display
            ecosystem_desc = ecosystem if ecosystem else ""
            # Create display message with ecosystem info if specified
            ecosystem_suffix = f" ({ecosystem})" if ecosystem else ""
            self.console.print(
                f"📦 Found {len(malicious_packages)} malicious packages from feed{ecosystem_suffix}",
                style="green",
            )

            # Show cache hit/miss statistics from the fetch
            if fetch_result.get("cache_stats"):
                cache_stats = fetch_result["cache_stats"]
                hits = cache_stats.get("last_fetch_hits", 0)
                misses = cache_stats.get("last_fetch_misses", 0)
                hit_rate = cache_stats.get("last_fetch_hit_rate", 0)
                if hits > 0 or misses > 0:
                    self.console.print(
                        f"💾 Cache: {hits} hits, {misses} misses ({hit_rate:.1f}% hit rate)",
                        style="cyan",
                    )

            # Show ecosystem breakdown if available and not filtering by single ecosystem
            if not ecosystem and fetch_result.get("ecosystems"):
                ecosystems = fetch_result["ecosystems"]
                for eco, count in ecosystems.items():
                    self.console.print(f"  • {eco}: {count} packages", style="blue")
                self.console.print()  # Add blank line for better readability

            # Step 2: Block packages (if selected)
            if block:
                self.console.print(
                    "\nStep 2: Blocking malicious packages in registry...",
                    style="yellow",
                )

                blocked_count = 0
                block_errors = 0

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=self.console,
                    transient=False,
                ) as progress:
                    block_task = progress.add_task(
                        "Blocking packages...", total=len(malicious_packages)
                    )

                    for package in malicious_packages:
                        try:
                            # Use the app's block functionality
                            block_result = await self.app.block_package_in_registry(
                                package.name, package.ecosystem, package.version or "*"
                            )

                            if block_result["success"]:
                                blocked_count += 1
                            else:
                                block_errors += 1

                        except Exception:
                            block_errors += 1

                        progress.advance(block_task, 1)
                        progress.update(
                            block_task,
                            description=f"Blocked: {blocked_count} | Errors: {block_errors}",
                        )

                self.console.print(
                    f"✅ Blocked {blocked_count} packages, {block_errors} errors",
                    style="green" if block_errors == 0 else "yellow",
                )

            # Step 3: Search for malicious packages in registry
            step_num = 3 if block else 2
            self.console.print(
                f"\nStep {step_num}: Searching for malicious packages in registry...",
                style="yellow",
            )

            # Calculate and display compression statistics
            from src.core.wildcard_compressor import WildcardCompressor

            compressor = WildcardCompressor(min_group_size=2)

            # Group packages by ecosystem
            packages_by_ecosystem = {}
            for pkg in malicious_packages:
                if pkg.ecosystem not in packages_by_ecosystem:
                    packages_by_ecosystem[pkg.ecosystem] = []
                packages_by_ecosystem[pkg.ecosystem].append(pkg)

            # Calculate compression for each ecosystem
            total_original = 0
            total_compressed = 0
            for eco, pkgs in packages_by_ecosystem.items():
                wildcard_groups, individual_packages = compressor.compress_packages(
                    pkgs
                )
                original_count = len(pkgs)
                compressed_count = len(wildcard_groups) + len(individual_packages)
                total_original += original_count
                total_compressed += compressed_count

            # Display compression stats
            if total_original > 0:
                reduction = ((total_original - total_compressed) / total_original) * 100
                compression_ratio = (
                    total_original / total_compressed if total_compressed > 0 else 1
                )
                self.console.print(
                    f"🗜️  Compression: {total_original} packages → {total_compressed} queries "
                    f"({reduction:.1f}% reduction, {compression_ratio:.2f}x compression)",
                    style="cyan",
                )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=False,
            ) as progress:
                analysis_task = progress.add_task(
                    "Cross-referencing malicious packages with package registry...",
                    total=None,
                )

                # Use the core app for business logic - pass already-fetched packages
                # to avoid fetching them again from OSV
                analysis_result = (
                    await self.app.security_analysis.crossref_analysis_with_packages(
                        malicious_packages=malicious_packages,
                        save_report=not no_report,
                        send_notifications=not no_notifications,
                        progress_callback=lambda msg, current, total: progress.update(
                            analysis_task, description=msg
                        ),
                    )
                )

                if not analysis_result["success"]:
                    progress.update(analysis_task, description="❌ Analysis failed")
                    if analysis_result.get("error"):
                        self.console.print(
                            f"❌ Error: {analysis_result['error']}", style="red"
                        )
                    return False

                progress.update(analysis_task, description="✅ Analysis complete")

            # Extract results
            found_matches = analysis_result["found_matches"]
            safe_packages = analysis_result["safe_packages"]
            errors = analysis_result["errors"]
            not_found_count = analysis_result["not_found_count"]
            total_checked = analysis_result["filtered_packages"]

            # Display results
            self.console.print("\n" + "=" * 80, style="bold")
            self.console.print("🛡️ SECURITY ANALYSIS RESULTS", style="bold cyan")
            self.console.print("=" * 80, style="bold")

            # Display ecosystem information
            ecosystems_scanned = analysis_result.get("ecosystems_scanned", [])
            if ecosystems_scanned:
                self.console.print(
                    f"🏗️ Ecosystems scanned: {', '.join(ecosystems_scanned)}",
                    style="blue",
                )
                if len(ecosystems_scanned) > 1:
                    self.console.print(
                        "📊 Multi-ecosystem analysis with registry-first optimization",
                        style="blue",
                    )
                self.console.print()

            # Get registry name and dynamic field names
            registry_name = await self._get_registry_name()
            field_names = await self._get_dynamic_field_names()

            if found_matches:
                self.console.print(
                    f"\n🚨 CRITICAL: {len(found_matches)} malicious packages found in {registry_name}!",
                    style="bold red",
                )

                for match in found_matches:
                    pkg = match["package"]
                    repositories_searched = match.get("repositories_searched", [])
                    self.console.print(f"\n❌ {pkg.name}", style="bold red")
                    self.console.print(
                        f"   📦\tMalicious versions: {', '.join(match['malicious_versions'])}"
                    )

                    # Check if all versions field exists (might not for injected test packages)
                    all_versions_field = field_names["all_versions_field"]
                    if all_versions_field in match and match[all_versions_field]:
                        self.console.print(
                            f"   🏗️\t{registry_name} versions: {', '.join(match[all_versions_field])}"
                        )
                    else:
                        self.console.print(
                            f"   🏗️\t{registry_name} versions: [Version info unavailable]"
                        )

                    self.console.print(
                        f"   ⚠️\tMATCHING VERSIONS: {', '.join(match['matching_versions'])}",
                        style="bold red",
                    )
                    if repositories_searched:
                        repos_display = ", ".join(repositories_searched)
                        if len(repos_display) > 60:  # Truncate if too long
                            repos_display = repos_display[:57] + "..."
                        self.console.print(
                            f"   🗂️\tRepositories searched: {repos_display}"
                        )
                    if hasattr(pkg, "package_url"):
                        self.console.print(f"   🔗\tPackage URL: {pkg.package_url}")

            if safe_packages:
                self.console.print(
                    f"\n⚠️ {len(safe_packages)} packages found but with different versions:",
                    style="yellow",
                )

                for safe in safe_packages:
                    pkg = safe["package"]
                    repositories_searched = safe.get("repositories_searched", [])
                    self.console.print(f"\n🟡 {pkg.name}", style="bright_green")
                    self.console.print(
                        f"   📦\tMalicious versions: {', '.join(safe['malicious_versions'])}"
                    )

                    # Check if registry versions field exists (might not for injected test packages)
                    versions_field = field_names["versions_field"]
                    if versions_field in safe and safe[versions_field]:
                        self.console.print(
                            f"   🏗️\t{registry_name} versions: {', '.join(safe[versions_field])}"
                        )
                    else:
                        self.console.print(
                            f"   🏗️\t{registry_name} versions: [Found in registry but version info unavailable]"
                        )

                    if repositories_searched:
                        repos_display = ", ".join(repositories_searched)
                        if len(repos_display) > 60:  # Truncate if too long
                            repos_display = repos_display[:57] + "..."
                        self.console.print(
                            f"   🗂️\tRepositories searched: {repos_display}"
                        )

            if not_found_count > 0:
                self.console.print(
                    f"\n🟢 {not_found_count} malicious packages not found in {registry_name}",
                    style="green",
                )

            if errors:
                self.console.print(
                    f"\n⚠️ {len(errors)} packages had search errors (timeouts/network issues):",
                    style="yellow",
                )
                for error in errors[:5]:  # Show first 5 errors
                    # Handle both dict and string error formats
                    if isinstance(error, dict):
                        pkg_name = error.get("package", "Unknown package")
                        error_msg = error.get("error", str(error))
                        # Handle case where package might be an object
                        if hasattr(pkg_name, "name"):
                            pkg_name = pkg_name.name
                    else:
                        pkg_name = "Unknown package"
                        error_msg = str(error)

                    # Truncate long error messages
                    if len(error_msg) > 100:
                        error_msg = error_msg[:100] + "..."

                    self.console.print(
                        f"   • {pkg_name}: {error_msg}",
                        style="dim",
                    )
                if len(errors) > 5:
                    self.console.print(
                        f"   ... and {len(errors) - 5} more errors", style="dim"
                    )

            # Summary
            self.console.print("\n📊 SUMMARY:", style="bold")
            self.console.print(f"   Total malicious packages checked: {total_checked}")
            self.console.print(
                f"   Critical matches (same versions): {len(found_matches)}",
                style="red" if found_matches else "white",
            )
            self.console.print(
                f"   Safe (different versions): {len(safe_packages)}",
                style="yellow" if safe_packages else "white",
            )
            self.console.print(
                f"   Search errors (timeouts): {len(errors)}",
                style="yellow" if errors else "white",
            )
            self.console.print(
                f"   Not found in package registry: {not_found_count}", style="green"
            )

            # Report saving status
            if analysis_result.get("report_saved"):
                scan_id = analysis_result.get("scan_id", "unknown")
                self.console.print(
                    f"   📄 Scan report saved (ID: {scan_id})", style="green"
                )
            elif no_report:
                self.console.print(
                    "   📄 Scan report not saved (--no-report flag used)", style="dim"
                )
            else:
                self.console.print(
                    "   📄 Scan report not saved (storage unavailable)", style="yellow"
                )

            return len(found_matches) == 0  # Return True if no critical matches found

        except Exception as e:
            self.console.print(
                f"❌ Error during security cross-reference: {e}", style="red"
            )
            return False

    async def scan_results_list(self, limit: int = 3) -> bool:
        """List recent scan results with summary information."""
        try:
            self.console.print(
                f"📊 Recent Scan Results (Last {limit})", style="bold cyan"
            )

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            # Get recent scan summaries
            summaries_result = await self.app.get_recent_scan_summaries(limit)

            if not summaries_result["success"]:
                error_msg = summaries_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Error retrieving scan summaries: {error_msg}", style="red"
                )
                return False

            summaries = summaries_result["summaries"]

            if not summaries:
                self.console.print("📝 No scan results found", style="yellow")
                return True

            # Create table for scan summaries
            table = Table(title=f"Recent Scan Results ({len(summaries)} scans)")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Date & Time", style="blue")
            table.add_column("Status", style="magenta")
            table.add_column("Packages Scanned", style="yellow")
            table.add_column("Findings", style="red")
            table.add_column("Duration", style="green")

            for summary in summaries:
                status_emoji = "✅" if summary.status == "success" else "❌"
                duration = (
                    f"{summary.execution_duration_seconds:.1f}s"
                    if summary.execution_duration_seconds
                    else "N/A"
                )
                findings_display = (
                    str(summary.findings_count) if summary.findings_count > 0 else "0"
                )
                findings_style = "red" if summary.findings_count > 0 else "green"

                table.add_row(
                    summary.scan_id,  # Full scan ID
                    summary.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    f"{status_emoji} {summary.status}",
                    str(summary.packages_scanned),
                    f"[{findings_style}]{findings_display}[/{findings_style}]",
                    duration,
                )

            self.console.print(table)
            self.console.print(
                "\n💡 Use 'scan results --scan-id <ID>' to view detailed results",
                style="dim",
            )
            return True

        except Exception as e:
            self.console.print(f"❌ Error retrieving scan results: {e}", style="red")
            return False

    async def scan_results_details(self, scan_id: str) -> bool:
        """Show detailed scan result with findings analysis."""
        try:
            self.console.print(f"🔍 Scan Result Details: {scan_id}", style="bold cyan")

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            # Get detailed scan result
            details_result = await self.app.get_scan_result_details(scan_id)

            if not details_result["success"]:
                error_msg = details_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Error retrieving scan details: {error_msg}", style="red"
                )
                return False

            details = details_result["details"]
            scan_result = details_result["scan_result"]
            found_matches = details_result["found_matches"]
            safe_packages = details_result["safe_packages"]
            not_found_count = details_result["not_found_count"]

            # Display scan metadata
            self.console.print("\n" + "=" * 80, style="bold")
            self.console.print("📋 SCAN METADATA", style="bold cyan")
            self.console.print("=" * 80, style="bold")

            metadata_table = Table()
            metadata_table.add_column("Property", style="cyan")
            metadata_table.add_column("Value", style="white")

            status_emoji = "✅" if scan_result.status.value == "success" else "❌"
            duration = (
                f"{scan_result.execution_duration_seconds:.1f}s"
                if scan_result.execution_duration_seconds
                else "N/A"
            )

            metadata_table.add_row("Scan ID", scan_result.scan_id)
            metadata_table.add_row(
                "Timestamp", scan_result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            )
            metadata_table.add_row(
                "Status", f"{status_emoji} {scan_result.status.value}"
            )
            metadata_table.add_row("Duration", duration)
            metadata_table.add_row(
                "Packages Scanned", str(scan_result.packages_scanned)
            )
            metadata_table.add_row("Total Findings", str(len(details.findings)))

            if scan_result.errors:
                metadata_table.add_row(
                    "Errors", f"{len(scan_result.errors)} errors occurred"
                )

            self.console.print(metadata_table)

            # Display the same analysis format as crossref command
            self.console.print("\n" + "=" * 80, style="bold")
            self.console.print("🛡️ SECURITY ANALYSIS RESULTS", style="bold cyan")
            self.console.print("=" * 80, style="bold")

            # Get registry name and dynamic field names
            registry_name = await self._get_registry_name()
            field_names = await self._get_dynamic_field_names()

            if found_matches:
                self.console.print(
                    f"\n🚨 CRITICAL: {len(found_matches)} malicious packages found in {registry_name}!",
                    style="bold red",
                )

                for match in found_matches:
                    pkg = match["package"]
                    self.console.print(f"\n❌ {pkg.name}", style="bold red")
                    self.console.print(
                        f"   📦 Malicious versions: {', '.join(match['malicious_versions'])}"
                    )

                    # Check if all versions field exists (might not for injected test packages)
                    all_versions_field = field_names["all_versions_field"]
                    if all_versions_field in match and match[all_versions_field]:
                        self.console.print(
                            f"   🏗️ {registry_name} versions: {', '.join(match[all_versions_field])}"
                        )
                    else:
                        self.console.print(
                            f"   🏗️ {registry_name} versions: [Version info unavailable]"
                        )

                    self.console.print(
                        f"   ⚠️ MATCHING VERSIONS: {', '.join(match['matching_versions'])}",
                        style="bold red",
                    )
                    if hasattr(pkg, "package_url") and pkg.package_url:
                        self.console.print(f"   🔗 Package URL: {pkg.package_url}")

            if safe_packages:
                self.console.print(
                    f"\n⚠️ {len(safe_packages)} packages found but with different versions:",
                    style="yellow",
                )

                for safe in safe_packages:
                    pkg = safe["package"]
                    self.console.print(f"\n🟡 {pkg.name}")
                    self.console.print(
                        f"   📦 Malicious versions: {', '.join(safe['malicious_versions'])}"
                    )
                    self.console.print(
                        f"   🏗️ {registry_name} versions: {', '.join(safe[field_names['versions_field']])} ✅"
                    )

            if not_found_count > 0:
                self.console.print(
                    f"\n✅ {not_found_count} malicious packages not found in {registry_name}",
                    style="green",
                )

            # Summary
            self.console.print("\n📊 SUMMARY:", style="bold")
            self.console.print(
                f"   Total malicious packages checked: {scan_result.packages_scanned}"
            )
            self.console.print(
                f"   Critical matches (same versions): {len(found_matches)}",
                style="red" if found_matches else "white",
            )
            self.console.print(
                f"   Safe (different versions): {len(safe_packages)}",
                style="yellow" if safe_packages else "white",
            )
            self.console.print(
                f"   Not found in package registry: {not_found_count}", style="green"
            )

            if scan_result.errors:
                self.console.print(
                    f"   Errors during scan: {len(scan_result.errors)}", style="red"
                )

            return True

        except Exception as e:
            self.console.print(f"❌ Error retrieving scan details: {e}", style="red")
            return False

    async def registry_block(
        self, package_name: str, ecosystem: str = "npm", version: str = "*"
    ) -> bool:
        """Block a package in the package registry using exclusion patterns."""
        try:
            self.console.print(
                f"🚫 Blocking package: {package_name} ({ecosystem}) version {version}"
            )

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            block_result = await self.app.registry_management.block_package(
                package_name, ecosystem, version
            )

            if block_result["success"]:
                if block_result.get("already_blocked"):
                    self.console.print(f"ℹ️ {block_result['message']}", style="blue")
                else:
                    self.console.print(f"✅ {block_result['message']}", style="green")
                    self.console.print(
                        "📝 Package will be prevented from being downloaded or cached",
                        style="blue",
                    )
                return True
            else:
                error_msg = block_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Failed to block {package_name}: {error_msg}", style="red"
                )
                return False

        except Exception as e:
            self.console.print(f"❌ Error blocking package: {e}", style="red")
            # Ensure session is properly closed on exception
            registry = self.services.get("registry")
            if registry:
                await registry.close()
            return False

    async def registry_list_blocked(self, ecosystem: str = "npm") -> bool:
        """List currently blocked packages by showing exclusion patterns."""
        try:
            self.console.print(
                f"📋 Listing blocked packages for ecosystem: {ecosystem}"
            )

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            list_result = await self.app.registry_management.list_blocked_packages(
                ecosystem
            )

            if not list_result["success"]:
                error_msg = list_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Failed to list blocked packages: {error_msg}", style="red"
                )
                return False

            blocked_packages = list_result["blocked_packages"]

            if not blocked_packages:
                self.console.print(
                    f"✅ No exclusion patterns found for {ecosystem} ecosystem",
                    style="green",
                )
                return True

            # Display results
            self.console.print(
                f"\n🔍 Found {len(blocked_packages)} exclusion patterns:", style="cyan"
            )

            table = Table()
            table.add_column("Repository", style="cyan")
            table.add_column("Pattern", style="magenta")
            table.add_column("Type", style="yellow")

            for pattern_info in blocked_packages:
                repo = pattern_info.get("repository", "Unknown")
                pattern = pattern_info.get("pattern", "Unknown")
                pattern_type = "Malifiscan" if "# Malifiscan:" in pattern else "Other"

                table.add_row(repo, pattern, pattern_type)

            self.console.print(table)
            return True

        except Exception as e:
            self.console.print(f"❌ Error listing blocked packages: {e}", style="red")
            return False

    async def registry_list_repos(self) -> bool:
        """List available ecosystems and their matching repositories."""
        try:
            self.console.print("📋 Listing ecosystems and repositories...")

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            list_result = (
                await self.app.registry_management.list_ecosystems_and_repositories()
            )

            if not list_result["success"]:
                error_msg = list_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Failed to list repositories: {error_msg}", style="red"
                )
                return False

            # Display results
            ecosystems = list_result["ecosystems"]
            registry_name = list_result.get("registry_name", "Package Registry")

            # Summary table
            summary_table = Table(
                title=f"Repository Discovery Summary - {registry_name}"
            )
            summary_table.add_column("Property", style="cyan")
            summary_table.add_column("Value", style="magenta")

            summary_table.add_row(
                "Registry Health",
                "✅ Healthy" if list_result["registry_healthy"] else "❌ Unhealthy",
            )
            summary_table.add_row(
                "Total Ecosystems", str(list_result["total_ecosystems"])
            )
            summary_table.add_row(
                "Total Repositories", str(list_result["total_repositories"])
            )

            self.console.print(summary_table)

            # Detailed ecosystem-repository mapping
            if ecosystems:
                self.console.print("\n🏗️ Ecosystem to Repository Mapping:")

                # Create detailed table
                details_table = Table()
                details_table.add_column("Ecosystem", style="cyan")
                details_table.add_column("Repository Count", style="yellow")
                details_table.add_column("Repository Names", style="white")

                for ecosystem, repositories in ecosystems.items():
                    repo_count = len(repositories)
                    if repositories:
                        repo_names = ", ".join(repositories)
                        # Truncate very long lists
                        if len(repo_names) > 80:
                            repo_names = repo_names[:77] + "..."
                    else:
                        repo_names = "None found"

                    # Style based on whether repositories were found
                    count_style = "green" if repo_count > 0 else "red"

                    details_table.add_row(
                        ecosystem,
                        f"[{count_style}]{repo_count}[/{count_style}]",
                        repo_names,
                    )

                self.console.print(details_table)

                # Show ecosystems with no repositories
                no_repos = [eco for eco, repos in ecosystems.items() if not repos]
                if no_repos:
                    self.console.print(
                        f"\n⚠️ Ecosystems with no repositories found: {', '.join(no_repos)}",
                        style="yellow",
                    )

            else:
                self.console.print(
                    "📝 No ecosystem information available", style="yellow"
                )

            return True

        except Exception as e:
            self.console.print(f"❌ Error listing repositories: {e}", style="red")
            return False

    async def registry_unblock(
        self, package_name: str, ecosystem: str = "npm", version: str = "*"
    ) -> bool:
        """Unblock a package in the package registry by removing exclusion patterns."""
        try:
            self.console.print(
                f"✅ Unblocking package: {package_name} ({ecosystem}) version {version}"
            )

            if not self.app or not self.app.registry_management:
                self.console.print(
                    "❌ Registry management not initialized", style="red"
                )
                return False

            # Use the registry management use case
            unblock_result = await self.app.registry_management.unblock_package(
                package_name, ecosystem, version
            )

            if unblock_result["success"]:
                if unblock_result.get("was_blocked"):
                    self.console.print(f"✅ {unblock_result['message']}", style="green")
                    self.console.print(
                        "📝 Exclusion patterns have been removed - package can now be downloaded",
                        style="blue",
                    )
                else:
                    self.console.print(f"ℹ️ {unblock_result['message']}", style="blue")
                return True
            else:
                error_msg = unblock_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Failed to unblock {package_name}: {error_msg}", style="red"
                )
                return False

        except Exception as e:
            self.console.print(f"❌ Error unblocking package: {e}", style="red")
            return False

    async def fetch_feed_packages(
        self,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None,
        hours: int = 48,
    ) -> bool:
        """Fetch fresh malicious packages from the packages feed."""
        try:
            time_desc = f" (last {hours} hours)" if hours else ""
            self.console.print(
                f"🔄 Fetching fresh malicious packages from packages feed{time_desc}..."
            )

            if not self.app or not self.app.feed_management:
                self.console.print("❌ Feed management not initialized", style="red")
                return False

            with Progress() as progress:
                task = progress.add_task("Fetching from packages feed...", total=100)

                # Use the feed management use case
                fetch_result = await self.app.feed_management.fetch_recent_packages(
                    ecosystem, limit, hours
                )
                progress.advance(task, 100)

            if not fetch_result["success"]:
                error_msg = fetch_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Error fetching packages: {error_msg}", style="red"
                )
                return False

            packages = fetch_result["packages"]
            ecosystem_counts = fetch_result["ecosystem_counts"]

            if not packages:
                filter_desc = f" for {ecosystem} ecosystem" if ecosystem else ""
                self.console.print(
                    f"📦 No malicious packages found{filter_desc}", style="yellow"
                )
                return True

            # Show summary
            self.console.print(
                f"🎯 Found {len(packages)} malicious packages from packages feed"
            )
            for eco, count in ecosystem_counts.items():
                self.console.print(f"  • {eco}: {count} packages")

            # Show packages
            title = f"Fresh Malicious Packages from Feed (Showing {len(packages)})"
            if ecosystem:
                title += f" - {ecosystem.upper()} only"

            table = Table(title=title)
            table.add_column("Name", style="cyan")
            table.add_column("Ecosystem", style="magenta")
            table.add_column("Version", style="blue")
            table.add_column("Advisory ID", style="yellow")
            table.add_column("Summary", style="white")

            for pkg in packages:
                summary = pkg.summary or pkg.details or "No description available"
                # Truncate long summaries
                if len(summary) > 50:
                    summary = summary[:47] + "..."

                table.add_row(
                    pkg.name,
                    pkg.ecosystem,
                    pkg.version or "N/A",
                    pkg.advisory_id,
                    summary,
                )

            self.console.print(table)
            return True

        except Exception as e:
            self.console.print(f"❌ Error fetching from feed: {e}", style="red")
            return False

    def _format_service_details(self, service_name: str, details) -> str:
        """
        Format service health details for display.

        Args:
            service_name: Name of the service
            details: Service details (bool, dict, or string)

        Returns:
            Formatted details string
        """
        # Handle cache service with dict response
        if service_name == "cache" and isinstance(details, dict):
            if "enabled" in details:
                if details.get("enabled"):
                    backend = details.get("backend", "unknown").title()
                    if details.get("healthy", True):
                        return f"✅ {backend} connected"
                    else:
                        return f"⚠️ {backend} unhealthy"
                else:
                    return "ℹ️ Cache disabled (no-cache mode)"

        # Handle boolean response
        if isinstance(details, bool):
            return (
                "Service is responding normally"
                if details
                else "Service is not responding"
            )

        # Handle string or other types
        return str(details)

    async def health_check(self) -> bool:
        """Check health of all services."""
        try:
            self.console.print("🏥 Checking service health...")

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            with Progress() as progress:
                task = progress.add_task("Checking services...", total=100)

                # Use the core app for business logic
                health_result = await self.app.get_service_health_status()
                progress.advance(task, 100)

            if not health_result["success"]:
                error_msg = health_result.get("error", "Unknown error")
                self.console.print(f"❌ Health check failed: {error_msg}", style="red")
                return False

            # Display results
            table = Table(title="Service Health Check")
            table.add_column("Service", style="cyan")
            table.add_column("Status", style="magenta")
            table.add_column("Details", style="blue")

            for service_name, health_info in health_result["services"].items():
                if health_info["healthy"]:
                    status = "✅ Healthy"
                elif health_info["status"] == "error":
                    status = "⚠️ Error"
                else:
                    status = "❌ Unhealthy"

                # Format details based on service type
                details = self._format_service_details(
                    service_name, health_info["details"]
                )

                table.add_row(service_name.title(), status, details)

            self.console.print(table)

            # Overall health
            if health_result["overall_healthy"]:
                self.console.print("🎉 All services are healthy!", style="green")
            else:
                healthy_count = health_result["healthy_count"]
                total_count = health_result["total_count"]
                self.console.print(
                    f"⚠️ {healthy_count}/{total_count} services are healthy",
                    style="yellow",
                )

            return health_result["overall_healthy"]

        except Exception as e:
            self.console.print(f"❌ Error during health check: {e}", style="red")
            return False

    async def notifications_check(self, malicious: bool = False) -> bool:
        """Test notification functionality by sending a test notification."""
        try:
            self.console.print("🔔 Testing Notification Service", style="bold cyan")

            if malicious:
                self.console.print(
                    "🚨 Testing with malicious package payload", style="yellow"
                )

            self.console.print()

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            # Check if notification service is available and configured
            notification_service = self.app.services.get("notification_service")
            if not notification_service:
                self.console.print("❌ Notification service not available", style="red")
                return False

            # Use the notification testing use case
            from src.core.usecases.notification_testing import (
                NotificationTestingUseCase,
            )

            notification_testing = NotificationTestingUseCase(notification_service)

            # Run notification test
            test_result = await notification_testing.test_notification_service(
                include_malicious=malicious
            )

            # Display results
            if not test_result.get("healthy", False):
                self.console.print(
                    "❌ Notification service health check failed", style="red"
                )
                self.console.print(
                    "💡 Ensure your notification service is properly configured:",
                    style="yellow",
                )
                self.console.print(
                    "  • For webhook: Set WEBHOOK_URL environment variable", style="dim"
                )
                self.console.print(
                    "  • For MS Teams: Set MSTEAMS_WEBHOOK_URL environment variable",
                    style="dim",
                )
                self.console.print("  • Verify webhook URL is accessible", style="dim")
                return False

            self.console.print("✅ Notification service is healthy", style="green")

            # Display test notification result
            if test_result.get("notification_sent"):
                test_type = test_result.get("test_type", "basic")
                if test_type == "malicious_package":
                    self.console.print(
                        "✅ Malicious package test notification sent successfully!",
                        style="green",
                    )
                    self.console.print("   Package: mal-test-pack@9.9.9", style="dim")
                    self.console.print(
                        f"   Affected packages: {test_result.get('affected_packages_count', 0)}",
                        style="dim",
                    )
                else:
                    self.console.print(
                        "✅ Test notification sent successfully!", style="green"
                    )

                self.console.print(
                    "Check your notification channel to confirm receipt.", style="dim"
                )

                if malicious:
                    self.console.print(
                        "\n💡 The malicious package notification simulates a real security alert",
                        style="yellow",
                    )
                    self.console.print(
                        "   with comprehensive package details and critical severity level.",
                        style="dim",
                    )

                return True
            else:
                self.console.print("❌ Failed to send test notification", style="red")
                if "error" in test_result:
                    self.console.print(f"   Error: {test_result['error']}", style="dim")
                return False

        except Exception as e:
            self.console.print(f"❌ Error testing notifications: {e}", style="red")
            logging.getLogger(__name__).exception("Error in notifications test")
            return False

    async def run_manual_scan(self) -> bool:
        """Run a manual security scan using the core app functionality."""
        try:
            self.console.print("🔍 Running manual security scan...", style="bold cyan")

            if not self.app:
                raise RuntimeError("Application not initialized")

            # Use the core app's scan functionality
            success = await self.app.run_single_scan()

            if success:
                self.console.print("✅ Scan completed successfully", style="green")
            else:
                self.console.print("❌ Scan failed", style="red")

            return success

        except Exception as e:
            self.console.print(f"❌ Error running scan: {e}", style="red")
            return False

    async def create_test_data(self) -> bool:
        """Create some test malicious packages for testing."""
        try:
            self.console.print("🧪 Creating test data...")

            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False

            # Use the core app for business logic
            test_result = await self.app.create_test_malicious_packages()

            if not test_result["success"]:
                error_msg = test_result.get("error", "Unknown error")
                self.console.print(
                    f"❌ Failed to create test packages: {error_msg}", style="red"
                )
                return False

            test_packages = test_result["packages_created"]
            self.console.print(
                f"✅ Created {test_result['count']} test packages", style="green"
            )

            table = Table(title="Test Packages Created")
            table.add_column("Name", style="cyan")
            table.add_column("Ecosystem", style="magenta")
            table.add_column("Advisory ID", style="blue")

            for pkg in test_packages:
                table.add_row(pkg.name, pkg.ecosystem, pkg.advisory_id)

            self.console.print(table)
            return True

        except Exception as e:
            self.console.print(f"❌ Error creating test data: {e}", style="red")
            return False

    async def cleanup_test_data(self) -> bool:
        """Clean up test data (packages with CLI-TEST advisory IDs)."""
        try:
            self.console.print("🧹 Cleaning up test data...")

            storage = self.services["storage"]
            packages = await storage.get_known_malicious_packages()

            # Find test packages
            test_packages = [
                pkg for pkg in packages if pkg.advisory_id.startswith("CLI-TEST")
            ]

            if not test_packages:
                self.console.print(
                    "📝 No test packages found to clean up", style="yellow"
                )
                return True

            self.console.print(f"Found {len(test_packages)} test packages to remove")

            # Note: We would need to add a delete method to the storage interface
            # For now, just show what would be deleted
            table = Table(title="Test Packages to Remove")
            table.add_column("Name", style="cyan")
            table.add_column("Ecosystem", style="magenta")
            table.add_column("Advisory ID", style="blue")

            for pkg in test_packages:
                table.add_row(pkg.name, pkg.ecosystem, pkg.advisory_id)

            self.console.print(table)
            self.console.print(
                "⚠️ Delete functionality needs to be implemented in storage interface",
                style="yellow",
            )

            return True

        except Exception as e:
            self.console.print(f"❌ Error cleaning up test data: {e}", style="red")
            return False

    async def config_init(self) -> bool:
        """Initialize local configuration files from templates."""
        try:
            self.console.print(
                "🔧 Initializing local configuration files...", style="cyan"
            )

            # Check if config.local.yaml already exists
            local_config_path = Path("config.local.yaml")
            overwrite = False
            if local_config_path.exists():
                if not Confirm.ask("config.local.yaml already exists. Overwrite?"):
                    self.console.print(
                        "❌ Configuration initialization cancelled", style="yellow"
                    )
                    return False
                overwrite = True

            # Use the configuration management usecase
            config_usecase = ConfigurationManagementUseCase(
                config_file=self.config_file,
                env_file=self.env_file,
                local_config_file="config.local.yaml",
            )

            success, message = await config_usecase.initialize_configuration(
                overwrite_existing=overwrite
            )

            if success:
                self.console.print(f"✅ {message}", style="green")
                self.console.print()
                self.console.print(
                    "🎉 Configuration initialization complete!", style="bold green"
                )
                self.console.print()
                self.console.print("Next steps:", style="bold")
                self.console.print(
                    "1. Edit config.local.yaml with your specific settings"
                )
                self.console.print(
                    "2. Edit .env with your JFrog credentials and other secrets"
                )
                self.console.print(
                    "3. Run 'python cli.py config validate' to verify your configuration"
                )
                return True
            else:
                self.console.print(f"❌ {message}", style="red")
                return False

        except Exception as e:
            self.console.print(f"❌ Error initializing configuration: {e}", style="red")
            return False

    async def config_show(self) -> bool:
        """Show current configuration from all sources."""
        try:
            self.console.print("📋 Current Configuration", style="bold cyan")
            self.console.print()

            # Use the configuration management usecase
            config_usecase = ConfigurationManagementUseCase(
                config_file=self.config_file,
                env_file=self.env_file,
                local_config_file="config.local.yaml",
            )

            success, config_summary = await config_usecase.get_configuration_summary()

            if not success:
                self.console.print("❌ Error loading configuration", style="red")
                return False

            # Create configuration display table
            table = Table(title="Configuration Summary")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            table.add_column("Source", style="yellow")

            # Add key configuration items
            settings = config_summary["settings"]
            table.add_row("Environment", settings["environment"], "config file")
            table.add_row("Debug Mode", str(settings["debug"]), "config file")
            table.add_row(
                "OSV Feed",
                f"{settings['osv_feed']['type']} ({'enabled' if settings['osv_feed']['enabled'] else 'disabled'})",
                "config file",
            )
            table.add_row(
                "Registry",
                f"{settings['registry']['type']} ({'enabled' if settings['registry']['enabled'] else 'disabled'})",
                "config file",
            )
            table.add_row(
                "Storage",
                f"{settings['storage']['type']} ({'enabled' if settings['storage']['enabled'] else 'disabled'})",
                "config file",
            )
            table.add_row(
                "Notifications",
                f"{settings['notifications']['type']} ({'enabled' if settings['notifications']['enabled'] else 'disabled'})",
                "config file",
            )
            table.add_row("Log Level", settings["log_level"], "config file")

            # Environment-based settings
            env_vars = config_summary["environment_vars"]
            if env_vars["jfrog_url"] != "not set":
                table.add_row("JFrog URL", env_vars["jfrog_url"], "environment")
            if env_vars["jfrog_username"] != "not set":
                table.add_row(
                    "JFrog Username", env_vars["jfrog_username"], "environment"
                )
            if env_vars["jfrog_api_key"] != "not set":
                table.add_row("JFrog API Key", env_vars["jfrog_api_key"], "environment")

            self.console.print(table)
            self.console.print()

            # Show file locations
            config_files_table = Table(title="Configuration Files")
            config_files_table.add_column("File", style="cyan")
            config_files_table.add_column("Status", style="green")
            config_files_table.add_column("Purpose", style="yellow")

            files_info = config_summary["files"]
            for filename, info in files_info.items():
                status = "✅ Found" if info["exists"] else "❌ Missing"
                config_files_table.add_row(filename, status, info["purpose"])

            self.console.print(config_files_table)

            return True

        except Exception as e:
            self.console.print(f"❌ Error showing configuration: {e}", style="red")
            return False

    async def config_validate(self) -> bool:
        """Validate current configuration."""
        try:
            self.console.print("🔍 Validating Configuration", style="bold cyan")
            self.console.print()

            # Use the configuration management usecase
            config_usecase = ConfigurationManagementUseCase(
                config_file=self.config_file,
                env_file=self.env_file,
                local_config_file="config.local.yaml",
            )

            success, validation_results = await config_usecase.validate_configuration()

            # Display validation results
            table = Table(title="Validation Results")
            table.add_column("Status", style="cyan")
            table.add_column("Check", style="white")

            for result in validation_results:
                table.add_row(result["status"], result["message"])

            self.console.print(table)

            # Summary
            errors = [r for r in validation_results if r["status"] == "❌"]
            warnings = [r for r in validation_results if r["status"] == "⚠️"]

            if errors:
                self.console.print(
                    f"\n❌ Validation failed with {len(errors)} error(s)", style="red"
                )
                return False
            elif warnings:
                self.console.print(
                    f"\n⚠️ Validation passed with {len(warnings)} warning(s)",
                    style="yellow",
                )
            else:
                self.console.print("\n✅ All validation checks passed!", style="green")

            return success

        except Exception as e:
            self.console.print(f"❌ Error validating configuration: {e}", style="red")
            return False


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Scanner CLI - Manual testing and administration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py registry search lodash npm
  python cli.py registry block evil-package npm 1.2.3
  python cli.py registry unblock evil-package npm 1.2.3
  python cli.py registry list-blocked npm
  python cli.py feed fetch --ecosystem npm --limit 50 --hours 24
  python cli.py scan crossref
  python cli.py scan crossref --block --hours 24 --ecosystem npm
  python cli.py health check
        """,
    )

    parser.add_argument(
        "--config", "-c", default="config.yaml", help="Configuration file"
    )
    parser.add_argument("--env", "-e", default=".env", help="Environment file")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Registry commands
    registry_parser = subparsers.add_parser(
        "registry", help="Package registry operations"
    )
    registry_subparsers = registry_parser.add_subparsers(dest="registry_action")

    health_parser = registry_subparsers.add_parser(
        "health", help="Check package registry health"
    )

    search_parser = registry_subparsers.add_parser(
        "search", help="Search for a package"
    )
    search_parser.add_argument("package_name", help="Package name to search")
    search_parser.add_argument(
        "ecosystem", nargs="?", default="npm", help="Package ecosystem"
    )

    block_parser = registry_subparsers.add_parser(
        "block", help="Block a package using exclusion patterns"
    )
    block_parser.add_argument("package_name", help="Package name to block")
    block_parser.add_argument(
        "ecosystem",
        nargs="?",
        default="npm",
        help="Package ecosystem (npm, PyPI, Maven, etc.)",
    )
    block_parser.add_argument(
        "version", nargs="?", default="*", help="Package version (* for all versions)"
    )

    unblock_parser = registry_subparsers.add_parser(
        "unblock", help="Unblock a package by removing exclusion patterns"
    )
    unblock_parser.add_argument("package_name", help="Package name to unblock")
    unblock_parser.add_argument(
        "ecosystem",
        nargs="?",
        default="npm",
        help="Package ecosystem (npm, PyPI, Maven, etc.)",
    )
    unblock_parser.add_argument(
        "version", nargs="?", default="*", help="Package version (* for all versions)"
    )

    list_blocked_parser = registry_subparsers.add_parser(
        "list-blocked", help="List currently blocked packages by ecosystem"
    )
    list_blocked_parser.add_argument(
        "ecosystem",
        nargs="?",
        default="npm",
        help="Package ecosystem (npm, PyPI, Maven, etc.)",
    )
    list_blocked_parser.add_argument(
        "--details", action="store_true", help="Show detailed pattern information"
    )

    registry_subparsers.add_parser(
        "list-repos", help="List available ecosystems and their matching repositories"
    )

    # Security scan command
    scan_parser = subparsers.add_parser("scan", help="Security scanning operations")
    scan_subparsers = scan_parser.add_subparsers(dest="scan_action")

    crossref_parser = scan_subparsers.add_parser(
        "crossref",
        help="Cross-reference malicious packages from feed with package registry",
    )
    crossref_parser.add_argument(
        "--hours",
        type=int,
        default=6,
        help="Hours ago to look for recent malicious packages (default: 6)",
    )
    crossref_parser.add_argument(
        "--ecosystem", help="Package ecosystem (default: all available ecosystems)"
    )
    crossref_parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of malicious packages to check (default: no limit)",
    )
    crossref_parser.add_argument(
        "--no-report", action="store_true", help="Skip saving scan report to storage"
    )
    crossref_parser.add_argument(
        "--block",
        action="store_true",
        help="Block malicious packages from OSV feed before searching (default: false)",
    )
    crossref_parser.add_argument(
        "--no-notifications",
        action="store_true",
        help="Disable sending notifications for critical findings (default: false)",
    )
    crossref_parser.add_argument(
        "--inject-packages",
        type=str,
        help='Inject additional test packages (format: "ecosystem:name:version,ecosystem:name:version"). Example: "npm:lodash:4.17.21,PyPI:requests:2.28.0"',
    )

    results_parser = scan_subparsers.add_parser(
        "results", help="View scan results and findings"
    )
    results_parser.add_argument(
        "--scan-id", type=str, help="Show detailed results for specific scan ID"
    )
    results_parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Number of recent scans to show (default: 3)",
    )

    # Feed commands
    feed_parser = subparsers.add_parser("feed", help="Packages feed operations")
    feed_subparsers = feed_parser.add_subparsers(dest="feed_action")

    fetch_parser = feed_subparsers.add_parser(
        "fetch", help="Fetch fresh packages from packages feed"
    )
    fetch_parser.add_argument(
        "--ecosystem", "-e", type=str, help="Filter by ecosystem (npm, pypi, etc.)"
    )
    fetch_parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Maximum number of packages to fetch (default: no limit)",
    )
    fetch_parser.add_argument(
        "--hours",
        type=int,
        default=48,
        help="Fetch packages modified within the last N hours (default: 48)",
    )

    # Health check
    health_parser = subparsers.add_parser("health", help="Service health operations")
    health_subparsers = health_parser.add_subparsers(dest="health_action")
    health_subparsers.add_parser("check", help="Check service health")

    # Notifications
    notifications_parser = subparsers.add_parser(
        "notifications", help="Notification service operations"
    )
    notifications_subparsers = notifications_parser.add_subparsers(
        dest="notifications_action"
    )

    notifications_check_parser = notifications_subparsers.add_parser(
        "check", help="Test notification functionality"
    )
    notifications_check_parser.add_argument(
        "--malicious",
        action="store_true",
        help="Test with malicious package payload (uses mal-test-pack@9.9.9)",
    )

    # Test data
    test_parser = subparsers.add_parser("test", help="Test data operations")
    test_subparsers = test_parser.add_subparsers(dest="test_action")
    test_subparsers.add_parser("create", help="Create test data")
    test_subparsers.add_parser("cleanup", help="Clean up test data")

    # Configuration management
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_action")
    config_subparsers.add_parser("init", help="Initialize local configuration files")
    config_subparsers.add_parser("show", help="Show current configuration")
    config_subparsers.add_parser("validate", help="Validate configuration")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize CLI
    cli = SecurityScannerCLI(args.config, args.env)

    try:
        await cli.initialize()

        # Route to appropriate command
        if args.command == "registry":
            if args.registry_action == "health":
                await cli.registry_health()
            elif args.registry_action == "search":
                await cli.registry_search(args.package_name, args.ecosystem)
            elif args.registry_action == "block":
                await cli.registry_block(
                    args.package_name, args.ecosystem, args.version
                )
            elif args.registry_action == "unblock":
                await cli.registry_unblock(
                    args.package_name, args.ecosystem, args.version
                )
            elif args.registry_action == "list-blocked":
                await cli.registry_list_blocked(args.ecosystem)
            elif args.registry_action == "list-repos":
                await cli.registry_list_repos()

        elif args.command == "feed":
            if args.feed_action == "fetch":
                await cli.fetch_feed_packages(args.ecosystem, args.limit, args.hours)

        elif args.command == "scan":
            if args.scan_action == "crossref":
                await cli.security_crossref(
                    args.hours,
                    args.ecosystem,
                    args.limit,
                    args.no_report,
                    args.block,
                    args.no_notifications,
                    args.inject_packages,
                )
            elif args.scan_action == "results":
                if args.scan_id:
                    await cli.scan_results_details(args.scan_id)
                else:
                    await cli.scan_results_list(args.limit)

        elif args.command == "health":
            if args.health_action == "check":
                await cli.health_check()

        elif args.command == "notifications":
            if args.notifications_action == "check":
                await cli.notifications_check(args.malicious)

        elif args.command == "test":
            if args.test_action == "create":
                await cli.create_test_data()
            elif args.test_action == "cleanup":
                await cli.cleanup_test_data()

        elif args.command == "config":
            if args.config_action == "init":
                await cli.config_init()
            elif args.config_action == "show":
                await cli.config_show()
            elif args.config_action == "validate":
                await cli.config_validate()

    except KeyboardInterrupt:
        cli.console.print("\n👋 Goodbye!", style="blue")
    except Exception as e:
        cli.console.print(f"❌ Fatal error: {e}", style="red")
        sys.exit(1)


def cli_entry_point():
    """Entry point for the installed malifiscan command."""
    asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())
