#!/usr/bin/env python3
"""
CLI tool for manual testing and administration of the Security Scanner.

This tool provides easy access to all core functionality for testing purposes:
- Search for packages in package registry
- Block/unblock packages manually  
- View scan logs and storage data
- Check service health
- Run manual scans
- Manage test data

Usage:
    python cli.py --help
    python cli.py registry search <package-name>
    python cli.py registry block <package-name> <ecosystem>
    python cli.py logs view --limit 10
    python cli.py scan run
    python cli.py health check
    python cli.py interactive  # Start interactive mode
"""

import asyncio
import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
import cmd

# Import our application components
from src.config import ConfigLoader, Config
from src.factories import ServiceFactory
from src.core.entities import MaliciousPackage, ScanResult, NotificationEvent, NotificationLevel
from src.core.usecases import SecurityScanner
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
            # Configure CLI-specific logging BEFORE app initialization (reduce verbosity for better UX)
            self._configure_cli_logging()
            
            # Create and initialize the main app
            self.app = SecurityScannerApp(self.config_file, self.env_file)
            await self.app.initialize()
            
            # Get references for convenience
            self.config = self.app.config
            self.services = {
                'feed': self.app.services["packages_feed"],
                'registry': self.app.services["packages_registry"],
                'notification': self.app.services["notification_service"],
                'storage': self.app.services["storage_service"],
                'scanner': self.app.security_scanner
            }
            
            self.console.print("✅ CLI initialized successfully", style="green")
            
        except Exception as e:
            self.console.print(f"❌ Failed to initialize CLI: {e}", style="red")
            raise
    
    def _configure_cli_logging(self):
        """Configure logging for CLI to reduce verbosity while keeping errors visible."""
        # Set most loggers to WARNING level to reduce noise
        verbose_modules = [
            'src.providers.feeds.osv_feed',
            'src.providers.registries.jfrog_registry',
            'src.core.usecases.security_analysis',
            'src.core.usecases.data_management',
            'src.factories.service_factory',
            'src.main',
            'asyncio',
            'httpx',
            'httpcore'
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
                    'fetching package',
                    'successfully parsed package',
                    'application initialized',
                    'application initialization complete',
                    'creating services',
                    'creating use cases',
                    'notification service is disabled',
                    'fetching malicious packages from osv',
                    'starting to fetch malicious packages',
                    'filtering packages modified after',
                    'attempting to read',
                    'successfully downloaded csv',
                    'found malicious package',
                    'found malicious packages',
                    'will fetch first',
                    'successfully fetched',
                    'fetched packages from osv feed'
                ]
                
                # Allow error and warning messages through
                if record.levelno >= logging.WARNING:
                    return True
                
                # Suppress INFO messages that match our patterns
                if record.levelno == logging.INFO:
                    for pattern in suppress_patterns:
                        if pattern in message:
                            return False
                
                return True
        
        # Apply filter to all handlers
        for handler in root_logger.handlers:
            handler.addFilter(CLILogFilter())

    async def registry_health(self) -> bool:
        """Check package registry health."""
        try:
            self.console.print("🔍 Checking package registry health...")
            
            registry = self.services['registry']
            is_healthy = await registry.health_check()
            
            if is_healthy:
                self.console.print("✅ Package registry is healthy", style="green")
                await registry.close()
                return True
            else:
                self.console.print("❌ Package registry health check failed", style="red")
                await registry.close()
                return False
                
        except Exception as e:
            self.console.print(f"❌ Error checking package registry health: {e}", style="red")
            registry = self.services.get('registry')
            if registry:
                await registry.close()
            return False

    async def registry_search(self, package_name: str, ecosystem: str = "npm") -> bool:
        """Search for a package in the package registry."""
        try:
            self.console.print(f"🔍 Searching for package: {package_name} ({ecosystem})")
            
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            # Use the core app for business logic
            search_result = await self.app.search_package_in_registry(package_name, ecosystem)
            
            if not search_result["success"]:
                if search_result.get("error"):
                    self.console.print(f"❌ Error: {search_result['error']}", style="red")
                else:
                    self.console.print("❌ Package registry is not accessible", style="red")
                return False
            
            # Display results using rich formatting
            table = Table(title=f"Package Search Results: {package_name}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="magenta")
            
            table.add_row("Package Name", search_result["package_name"])
            table.add_row("Ecosystem", search_result["ecosystem"])
            table.add_row("Registry Health", "✅ Healthy" if search_result["registry_healthy"] else "❌ Unhealthy")
            table.add_row("Search Results", f"{search_result['results_count']} packages found")
            table.add_row("Currently Blocked", "🚫 Yes" if search_result["is_blocked"] else "✅ No")
            
            self.console.print(table)
            
            # Display detailed search results if any found
            search_results = search_result["search_results"]
            if search_results:
                self.console.print(f"\n📦 Found {len(search_results)} matching packages:")
                results_table = Table()
                results_table.add_column("Name", style="cyan")
                results_table.add_column("Version", style="magenta")
                results_table.add_column("Path", style="white")
                results_table.add_column("Size", style="yellow") 
                results_table.add_column("Modified", style="green")
                
                for result in search_results[:10]:  # Limit to first 10 results
                    size_str = f"{result.get('size', 0):,} bytes" if result.get('size') else "Unknown"
                    modified = result.get('modified', 'Unknown')[:19]  # Truncate timestamp
                    version = result.get('version', 'Unknown')
                    results_table.add_row(
                        result.get('name', 'Unknown'),
                        version,
                        result.get('path', 'Unknown'),
                        size_str,
                        modified
                    )
                
                self.console.print(results_table)
                
                if len(search_results) > 10:
                    self.console.print(f"... and {len(search_results) - 10} more results")
            
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error searching package: {e}", style="red")
            return False

    async def security_crossref(self, hours: int = 6, ecosystem: str = "npm", limit: Optional[int] = None, no_report: bool = False) -> bool:
        """Cross-reference malicious packages from feed with package registry."""
        try:
            self.console.print(f"🔍 Security Cross-Reference Analysis", style="bold cyan")
            self.console.print(f"📅 Looking for malicious packages from the last {hours} hours")
            self.console.print(f"🏗️ Ecosystem: {ecosystem}")
            self.console.print()
            
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            # Step 1: Show progress for feed fetch
            self.console.print("Step 1: Fetching recent malicious packages from feed...", style="yellow")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=False
            ) as progress:
                fetch_task = progress.add_task("Running security cross-reference analysis...", total=None)
                
                # Use the core app for business logic
                analysis_result = await self.app.security_crossref_analysis(hours, ecosystem, limit, not no_report)
                
                if not analysis_result["success"]:
                    progress.update(fetch_task, description=f"❌ Analysis failed")
                    if analysis_result.get("error"):
                        self.console.print(f"❌ Error: {analysis_result['error']}", style="red")
                    return False
                
                progress.update(fetch_task, description=f"✅ Analysis complete")
            
            # Extract results
            found_matches = analysis_result["found_matches"]
            safe_packages = analysis_result["safe_packages"]
            errors = analysis_result["errors"]
            not_found_count = analysis_result["not_found_count"]
            total_checked = analysis_result["filtered_packages"]
            
            if total_checked == 0:
                self.console.print(f"✅ No malicious {ecosystem} packages found in the last {hours} hours", style="green")
                return True
            
            self.console.print(f"⚠️ Found {total_checked} malicious {ecosystem} packages to check", style="yellow")
            
            # Step 2: Show progress for package registry cross-reference
            self.console.print("\nStep 2: Cross-referencing with package registry...", style="yellow")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("• Found: {task.fields[found]} | Safe: {task.fields[safe]} | Errors: {task.fields[errors]}"),
                console=self.console,
                transient=False
            ) as progress:
                task = progress.add_task(
                    "Processing results...", 
                    total=total_checked,
                    found=len(found_matches),
                    safe=len(safe_packages),
                    errors=len(errors)
                )
                progress.advance(task, total_checked)
            
            # Step 3: Display results
            self.console.print("\n" + "="*80, style="bold")
            self.console.print("🛡️ SECURITY ANALYSIS RESULTS", style="bold cyan")
            self.console.print("="*80, style="bold")
            
            if found_matches:
                self.console.print(f"\n🚨 CRITICAL: {len(found_matches)} malicious packages found in JFrog!", style="bold red")
                
                for match in found_matches:
                    pkg = match['package']
                    self.console.print(f"\n❌ {pkg.name}", style="bold red")
                    self.console.print(f"   📦 Malicious versions: {', '.join(match['malicious_versions'])}")
                    self.console.print(f"   🏗️ JFrog versions: {', '.join(match['all_jfrog_versions'])}")
                    self.console.print(f"   ⚠️ MATCHING VERSIONS: {', '.join(match['matching_versions'])}", style="bold red")
                    if hasattr(pkg, 'package_url'):
                        self.console.print(f"   🔗 Package URL: {pkg.package_url}")
            
            if safe_packages:
                self.console.print(f"\n⚠️ {len(safe_packages)} packages found but with different versions:", style="yellow")
                
                for safe in safe_packages:
                    pkg = safe['package']
                    self.console.print(f"\n🟡 {pkg.name}")
                    self.console.print(f"   📦 Malicious versions: {', '.join(safe['malicious_versions'])}")
                    self.console.print(f"   🏗️ JFrog versions: {', '.join(safe['jfrog_versions'])} ✅")
            
            if not_found_count > 0:
                self.console.print(f"\n✅ {not_found_count} malicious packages not found in JFrog", style="green")
            
            if errors:
                self.console.print(f"\n⚠️ {len(errors)} packages had search errors (timeouts/network issues):", style="yellow")
                for error in errors[:5]:  # Show first 5 errors
                    self.console.print(f"   • {error['package']}: {error['error'][:100]}...", style="dim")
                if len(errors) > 5:
                    self.console.print(f"   ... and {len(errors) - 5} more errors", style="dim")
            
            # Summary
            self.console.print(f"\n📊 SUMMARY:", style="bold")
            self.console.print(f"   Total malicious packages checked: {total_checked}")
            self.console.print(f"   Critical matches (same versions): {len(found_matches)}", style="red" if found_matches else "white")
            self.console.print(f"   Safe (different versions): {len(safe_packages)}", style="yellow" if safe_packages else "white")
            self.console.print(f"   Search errors (timeouts): {len(errors)}", style="yellow" if errors else "white")
            self.console.print(f"   Not found in package registry: {not_found_count}", style="green")
            
            # Report saving status
            if analysis_result.get("report_saved"):
                scan_id = analysis_result.get("scan_id", "unknown")
                self.console.print(f"   📄 Scan report saved (ID: {scan_id})", style="green")
            elif no_report:
                self.console.print(f"   📄 Scan report not saved (--no-report flag used)", style="dim")
            else:
                self.console.print(f"   📄 Scan report not saved (storage unavailable)", style="yellow")
            
            return len(found_matches) == 0  # Return True if no critical matches found
            
        except Exception as e:
            self.console.print(f"❌ Error during security cross-reference: {e}", style="red")
            return False

    async def security_crossref_test(self, ecosystem: str = "npm") -> bool:
        """Test cross-reference functionality with a known package (axios)."""
        try:
            self.console.print(f"🧪 Security Cross-Reference TEST", style="bold cyan")
            self.console.print(f"Testing with axios version 1.12.2 (known to exist in package registry)")
            self.console.print(f"🏗️ Ecosystem: {ecosystem}")
            self.console.print()
            
            # Create a fake malicious package entry for axios 1.12.2 (for testing)
            from src.core.entities.malicious_package import MaliciousPackage
            from datetime import datetime
            
            test_malicious_packages = [
                MaliciousPackage(
                    name="axios",
                    version="1.12.2",
                    ecosystem="npm",
                    package_url="pkg:npm/axios@1.12.2",
                    advisory_id="TEST-AXIOS-2025",
                    summary="TEST: Malicious code in axios (for testing cross-reference)",
                    details="This is a test entry to verify cross-reference functionality",
                    aliases=["TEST-AXIOS"],
                    affected_versions=["1.12.2"],
                    database_specific={},
                    published_at=datetime.now(),
                    modified_at=datetime.now()
                )
            ]
            
            self.console.print(f"⚠️ Created test malicious package: {test_malicious_packages[0].name} v{test_malicious_packages[0].version}")
            
            # Step 2: Check against package registry
            self.console.print("\nStep 2: Cross-referencing with package registry...", style="yellow")
            
            registry = self.services['registry']
            
            # Check package registry health first
            if not await registry.health_check():
                self.console.print("❌ Package registry is not accessible", style="red")
                return False
            
            found_matches = []
            safe_packages = []
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
                transient=True
            ) as progress:
                task = progress.add_task("Checking packages...", total=len(test_malicious_packages))
                
                for malicious_pkg in test_malicious_packages:
                    progress.update(task, description=f"Checking {malicious_pkg.name}")
                    
                    # Search for this package in JFrog
                    jfrog_results = await registry.search_packages(malicious_pkg.name, ecosystem)
                    
                    if jfrog_results:
                        # Check if any versions match
                        jfrog_versions = [result.get('version', '') for result in jfrog_results if result.get('version')]
                        malicious_versions = malicious_pkg.affected_versions
                        
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
                        else:
                            safe_packages.append({
                                'package': malicious_pkg,
                                'jfrog_results': jfrog_results,
                                'jfrog_versions': jfrog_versions,
                                'malicious_versions': malicious_versions
                            })
                    
                    progress.advance(task)
            
            # Step 3: Display results
            self.console.print("\n" + "="*80, style="bold")
            self.console.print("🛡️ TEST RESULTS", style="bold cyan")
            self.console.print("="*80, style="bold")
            
            if found_matches:
                self.console.print(f"\n✅ SUCCESS: Test detected malicious package in JFrog!", style="bold green")
                
                for match in found_matches:
                    pkg = match['package']
                    self.console.print(f"\n❌ {pkg.name}", style="bold red")
                    self.console.print(f"   📦 Malicious versions: {', '.join(match['malicious_versions'])}")
                    self.console.print(f"   🏗️ JFrog versions: {', '.join(match['all_jfrog_versions'])}")
                    self.console.print(f"   ⚠️ MATCHING VERSIONS: {', '.join(match['matching_versions'])}", style="bold red")
                    self.console.print(f"   🔗 Package URL: {pkg.package_url}")
                    
                self.console.print(f"\n🎯 TEST PASSED: Cross-reference logic is working correctly!", style="bold green")
            else:
                self.console.print(f"\n❌ TEST FAILED: Should have detected axios 1.12.2 as malicious!", style="bold red")
                if safe_packages:
                    for safe in safe_packages:
                        pkg = safe['package']
                        self.console.print(f"\n🟡 {pkg.name} found but versions don't match:")
                        self.console.print(f"   📦 Expected malicious: {', '.join(safe['malicious_versions'])}")
                        self.console.print(f"   🏗️ JFrog versions: {', '.join(safe['jfrog_versions'])}")
            
            # Clean up connections
            await registry.close()
            
            return len(found_matches) > 0  # Return True if test passed
            
        except Exception as e:
            self.console.print(f"❌ Error during test: {e}", style="red")
            registry = self.services.get('registry')
            if registry:
                await registry.close()
            return False

    async def registry_block(self, package_name: str, ecosystem: str = "npm", version: str = "*") -> bool:
        """Block a package in the package registry."""
        try:
            self.console.print(f"🚫 Blocking package: {package_name} ({ecosystem})")
            
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            # Use the core app for business logic
            block_result = await self.app.block_package_in_registry(package_name, ecosystem, version)
            
            if block_result["success"]:
                self.console.print(f"✅ Successfully blocked {package_name}", style="green")
                return True
            else:
                error_msg = block_result.get("error", "Unknown error")
                self.console.print(f"❌ Failed to block {package_name}: {error_msg}", style="red")
                return False
                
        except Exception as e:
            self.console.print(f"❌ Error blocking package: {e}", style="red")
            return False

    async def registry_unblock(self, package_name: str, ecosystem: str = "npm") -> bool:
        """Unblock a package in the package registry."""
        try:
            self.console.print(f"✅ Unblocking package: {package_name} ({ecosystem})")
            
            registry = self.services['registry']
            
            # Create package object
            package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version="*",
                package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                advisory_id="CLI-MANUAL-UNBLOCK",
                summary=f"Manually unblocked via CLI at {datetime.now()}",
                details="Package unblocked using CLI testing tool",
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=None,
                modified_at=None
            )
            
            # Note: We would need to add unblock_package method to the registry interface
            # For now, this is a placeholder to show the structure
            self.console.print("⚠️ Unblock functionality needs to be implemented in package registry", style="yellow")
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error unblocking package: {e}", style="red")
            return False

    async def view_logs(self, limit: int = 20, filter_level: Optional[str] = None) -> bool:
        """View scan results and logs from storage."""
        try:
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            # Use the core app for business logic
            logs_result = await self.app.get_scan_logs_data(limit, filter_level)
            
            if not logs_result["success"]:
                error_msg = logs_result.get("error", "Unknown error")
                self.console.print(f"❌ Error retrieving logs: {error_msg}", style="red")
                return False
            
            scan_results = logs_result["scan_results"]
            
            if not scan_results:
                self.console.print("📝 No scan results found", style="yellow")
                return True
            
            # Create table for scan results
            table = Table(title=f"Recent Scan Results (Last {len(scan_results)})")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Status", style="magenta")
            table.add_column("Started", style="blue")
            table.add_column("Duration", style="green")
            table.add_column("Packages Found", style="red")
            table.add_column("Packages Blocked", style="yellow")
            
            for result in scan_results:
                status_emoji = "✅" if result.success else "❌"
                duration = f"{result.duration_seconds:.1f}s" if result.duration_seconds else "N/A"
                
                table.add_row(
                    result.scan_id[:8],  # Short ID
                    f"{status_emoji} {result.status.value}",
                    result.started_at.strftime("%Y-%m-%d %H:%M"),
                    duration,
                    str(len(result.packages_found)),
                    str(result.blocked_packages)
                )
            
            self.console.print(table)
            
            # Show any error details
            for result in scan_results[:5]:  # Show details for recent failed scans
                if not result.success and result.error_message:
                    self.console.print(
                        Panel(
                            f"Error in scan {result.scan_id[:8]}: {result.error_message}",
                            title="Recent Error",
                            border_style="red"
                        )
                    )
            
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error viewing logs: {e}", style="red")
            return False

    async def view_malicious_packages(self, limit: int = 20, ecosystem: Optional[str] = None, hours: Optional[int] = None) -> bool:
        """View known malicious packages from storage."""
        try:
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            # Use the core app for business logic
            packages_result = await self.app.get_malicious_packages_data(limit, ecosystem, hours)
            
            if not packages_result["success"]:
                error_msg = packages_result.get("error", "Unknown error")
                self.console.print(f"❌ Error retrieving packages: {error_msg}", style="red")
                return False
            
            packages = packages_result["filtered_packages"]
            ecosystems = packages_result["ecosystems"]
            filter_info = packages_result["filter_info"]
            
            if not packages:
                filter_desc = f" ({ecosystem} ecosystem)" if ecosystem else ""
                time_desc = f" (last {hours} hours)" if hours else ""
                self.console.print(f"📦 No malicious packages found{filter_desc}{time_desc}", style="yellow")
                return True
            
            # Show summary first
            filter_info_display = ""
            if ecosystem:
                filter_info_display += f" (filtered to {ecosystem})"
            if hours:
                filter_info_display += f" (last {hours} hours)"
                
            self.console.print(f"📊 Total malicious packages: {packages_result['total_packages']}{filter_info_display}")
            for eco, count in ecosystems.items():
                self.console.print(f"  • {eco}: {count} packages")
            
            # Show packages table
            title = f"Known Malicious Packages (Showing {len(packages)})"
            if ecosystem:
                title += f" - {ecosystem.upper()} only"
            if hours:
                title += f" - Last {hours}h"
                
            table = Table(title=title)
            table.add_column("Name", style="cyan")
            table.add_column("Ecosystem", style="magenta")
            table.add_column("Version", style="blue")
            table.add_column("Modified", style="green")
            table.add_column("Advisory ID", style="yellow")
            table.add_column("Summary", style="white")
            
            for pkg in packages:
                # Format the modified/published date
                pkg_time = pkg.modified_at or pkg.published_at
                time_str = pkg_time.strftime("%Y-%m-%d %H:%M") if pkg_time else "N/A"
                
                table.add_row(
                    pkg.name,
                    pkg.ecosystem,
                    pkg.version or "N/A",
                    time_str,
                    pkg.advisory_id,
                    (pkg.summary[:40] + "...") if pkg.summary and len(pkg.summary) > 40 else pkg.summary or "N/A"
                )
            
            self.console.print(table)
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error viewing malicious packages: {e}", style="red")
            return False

    async def fetch_feed_packages(self, ecosystem: Optional[str] = None, limit: int = 100, hours: int = 48) -> bool:
        """Fetch fresh malicious packages from the packages feed."""
        try:
            time_desc = f" (last {hours} hours)" if hours else ""
            self.console.print(f"🔄 Fetching fresh malicious packages from packages feed{time_desc}...")
            
            if not self.app:
                self.console.print("❌ Application not initialized", style="red")
                return False
            
            with Progress() as progress:
                task = progress.add_task("Fetching from packages feed...", total=100)
                
                # Use the core app for business logic
                fetch_result = await self.app.fetch_packages_feed_data(ecosystem, limit, hours)
                progress.advance(task, 100)
            
            if not fetch_result["success"]:
                error_msg = fetch_result.get("error", "Unknown error")
                self.console.print(f"❌ Error fetching packages: {error_msg}", style="red")
                return False
            
            packages = fetch_result["packages"]
            ecosystems = fetch_result["ecosystems"]
            
            if not packages:
                filter_desc = f" for {ecosystem} ecosystem" if ecosystem else ""
                self.console.print(f"📦 No malicious packages found{filter_desc}", style="yellow")
                return True
            
            # Show summary
            self.console.print(f"🎯 Found {len(packages)} malicious packages from packages feed")
            for eco, count in ecosystems.items():
                self.console.print(f"  • {eco}: {count} packages")
            
            # Show most recent packages
            recent_packages = packages[:limit]
            
            title = f"Fresh Malicious Packages from Feed (Showing {len(recent_packages)})"
            if ecosystem:
                title += f" - {ecosystem.upper()} only"
                
            table = Table(title=title)
            table.add_column("Name", style="cyan")
            table.add_column("Ecosystem", style="magenta") 
            table.add_column("Version", style="blue")
            table.add_column("Severity", style="red")
            table.add_column("Advisory ID", style="yellow")
            table.add_column("Summary", style="white")
            
            for pkg in recent_packages:
                severity = "N/A"
                if pkg.database_specific and isinstance(pkg.database_specific, dict):
                    severity = pkg.database_specific.get('severity', 'N/A')
                    
                table.add_row(
                    pkg.name,
                    pkg.ecosystem,
                    pkg.version or "N/A",
                    severity,
                    pkg.advisory_id,
                    (pkg.summary[:35] + "...") if pkg.summary and len(pkg.summary) > 35 else pkg.summary or "N/A"
                )
            
            self.console.print(table)
            
            # Ask if user wants to store these packages
            if packages:
                store = Confirm.ask(f"\n💾 Store these {len(packages)} packages in local storage?")
                if store:
                    storage = self.services['storage']
                    await storage.store_malicious_packages(packages)
                    self.console.print(f"✅ Stored {len(packages)} packages in local storage", style="green")
            
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error fetching from OSV feed: {e}", style="red")
            return False

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
                
                table.add_row(service_name.title(), status, health_info["details"])
            
            self.console.print(table)
            
            # Overall health
            if health_result["overall_healthy"]:
                self.console.print("🎉 All services are healthy!", style="green")
            else:
                healthy_count = health_result["healthy_count"]
                total_count = health_result["total_count"]
                self.console.print(f"⚠️ {healthy_count}/{total_count} services are healthy", style="yellow")
            
            return health_result["overall_healthy"]
            
        except Exception as e:
            self.console.print(f"❌ Error during health check: {e}", style="red")
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
                self.console.print(f"❌ Failed to create test packages: {error_msg}", style="red")
                return False
            
            test_packages = test_result["packages_created"]
            self.console.print(f"✅ Created {test_result['count']} test packages", style="green")
            
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
            
            storage = self.services['storage']
            packages = await storage.get_known_malicious_packages()
            
            # Find test packages
            test_packages = [pkg for pkg in packages if pkg.advisory_id.startswith("CLI-TEST")]
            
            if not test_packages:
                self.console.print("📝 No test packages found to clean up", style="yellow")
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
            self.console.print("⚠️ Delete functionality needs to be implemented in storage interface", style="yellow")
            
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error cleaning up test data: {e}", style="red")
            return False


class InteractiveCLI(cmd.Cmd):
    """Interactive command line interface."""
    
    intro = '''
🔒 Security Scanner Interactive CLI
Type 'help' or '?' for available commands.
Type 'exit' or press Ctrl+C to quit.
    '''
    prompt = '(security-scanner) '
    
    def __init__(self, cli: SecurityScannerCLI):
        super().__init__()
        self.cli = cli
    
    def do_search(self, line):
        """Search for a package: search <package-name> [ecosystem]"""
        parts = line.split()
        if not parts:
            print("Usage: search <package-name> [ecosystem]")
            return
        
        package_name = parts[0]
        ecosystem = parts[1] if len(parts) > 1 else "npm"
        
        asyncio.run(self.cli.registry_search(package_name, ecosystem))
    
    def do_block(self, line):
        """Block a package: block <package-name> [ecosystem] [version]"""
        parts = line.split()
        if not parts:
            print("Usage: block <package-name> [ecosystem] [version]")
            return
        
        package_name = parts[0]
        ecosystem = parts[1] if len(parts) > 1 else "npm"
        version = parts[2] if len(parts) > 2 else "*"
        
        asyncio.run(self.cli.registry_block(package_name, ecosystem, version))
    
    def do_logs(self, line):
        """View logs: logs [limit]"""
        limit = int(line) if line.strip() else 20
        asyncio.run(self.cli.view_logs(limit))
    
    def do_packages(self, line):
        """View malicious packages: packages [limit] [ecosystem] [hours]"""
        parts = line.strip().split() if line.strip() else []
        limit = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 20
        ecosystem = parts[1] if len(parts) > 1 else None
        hours = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        asyncio.run(self.cli.view_malicious_packages(limit, ecosystem, hours))
    
    def do_health(self, line):
        """Check service health: health"""
        asyncio.run(self.cli.health_check())
    
    def do_scan(self, line):
        """Run manual scan: scan"""
        asyncio.run(self.cli.run_manual_scan())
    
    def do_feed(self, line):
        """Fetch from packages feed: feed [ecosystem] [limit]"""
        parts = line.strip().split() if line.strip() else []
        ecosystem = parts[0] if len(parts) > 0 else None
        limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 100
        hours = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 48
        asyncio.run(self.cli.fetch_feed_packages(ecosystem, limit, hours))
    
    def do_testdata(self, line):
        """Create test data: testdata"""
        asyncio.run(self.cli.create_test_data())
    
    def do_cleanup(self, line):
        """Clean up test data: cleanup"""
        asyncio.run(self.cli.cleanup_test_data())
    
    def do_exit(self, line):
        """Exit the interactive CLI"""
        print("Goodbye! 👋")
        return True
    
    def do_quit(self, line):
        """Exit the interactive CLI"""
        return self.do_exit(line)


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Scanner CLI - Manual testing and administration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py registry search lodash npm
  python cli.py registry block evil-package npm  
  python cli.py logs view --limit 10
  python cli.py logs packages --ecosystem npm --hours 72
  python cli.py feed fetch --ecosystem npm --limit 50 --hours 24
  python cli.py scan run
  python cli.py health check
  python cli.py interactive
        """
    )
    
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file")
    parser.add_argument("--env", "-e", default=".env", help="Environment file")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Registry commands
    registry_parser = subparsers.add_parser("registry", help="Package registry operations")
    registry_subparsers = registry_parser.add_subparsers(dest="registry_action")
    
    health_parser = registry_subparsers.add_parser("health", help="Check package registry health")
    
    search_parser = registry_subparsers.add_parser("search", help="Search for a package")
    search_parser.add_argument("package_name", help="Package name to search")
    search_parser.add_argument("ecosystem", nargs="?", default="npm", help="Package ecosystem")
    
    block_parser = registry_subparsers.add_parser("block", help="Block a package")
    block_parser.add_argument("package_name", help="Package name to block")
    block_parser.add_argument("ecosystem", nargs="?", default="npm", help="Package ecosystem")
    block_parser.add_argument("version", nargs="?", default="*", help="Package version")
    
    # Security scan command
    scan_parser = subparsers.add_parser("scan", help="Security scanning operations")
    scan_subparsers = scan_parser.add_subparsers(dest="scan_action")
    
    crossref_parser = scan_subparsers.add_parser("crossref", help="Cross-reference malicious packages from feed with package registry")
    crossref_parser.add_argument("--hours", type=int, default=6, help="Hours ago to look for recent malicious packages (default: 6)")
    crossref_parser.add_argument("--ecosystem", default="npm", help="Package ecosystem (default: npm)")
    crossref_parser.add_argument("--limit", type=int, help="Maximum number of malicious packages to check (default: no limit)")
    crossref_parser.add_argument("--no-report", action="store_true", help="Skip saving scan report to storage")
    
    test_parser = scan_subparsers.add_parser("test", help="Test cross-reference functionality with known package")
    test_parser.add_argument("--ecosystem", default="npm", help="Package ecosystem (default: npm)")
    
    # Logs commands
    logs_parser = subparsers.add_parser("logs", help="View logs and scan results")
    logs_subparsers = logs_parser.add_subparsers(dest="logs_action")
    
    view_parser = logs_subparsers.add_parser("view", help="View scan results")
    view_parser.add_argument("--limit", "-l", type=int, default=20, help="Number of results to show")
    
    packages_parser = logs_subparsers.add_parser("packages", help="View malicious packages")
    packages_parser.add_argument("--limit", "-l", type=int, default=20, help="Number of packages to show")
    packages_parser.add_argument("--ecosystem", "-e", type=str, help="Filter by ecosystem (npm, pypi, etc.)")
    packages_parser.add_argument("--hours", type=int, help="Show packages from last N hours")
    
    # Feed commands
    feed_parser = subparsers.add_parser("feed", help="Packages feed operations")
    feed_subparsers = feed_parser.add_subparsers(dest="feed_action")
    
    fetch_parser = feed_subparsers.add_parser("fetch", help="Fetch fresh packages from packages feed")
    fetch_parser.add_argument("--ecosystem", "-e", type=str, help="Filter by ecosystem (npm, pypi, etc.)")
    fetch_parser.add_argument("--limit", "-l", type=int, default=100, help="Number of packages to show")
    fetch_parser.add_argument("--hours", type=int, default=48, help="Fetch packages modified within the last N hours (default: 48)")
    
    # Health check
    health_parser = subparsers.add_parser("health", help="Service health operations")
    health_subparsers = health_parser.add_subparsers(dest="health_action")
    health_subparsers.add_parser("check", help="Check service health")
    
    # Test data
    test_parser = subparsers.add_parser("test", help="Test data operations")
    test_subparsers = test_parser.add_subparsers(dest="test_action")
    test_subparsers.add_parser("create", help="Create test data")
    test_subparsers.add_parser("cleanup", help="Clean up test data")
    
    # Interactive mode
    subparsers.add_parser("interactive", help="Start interactive mode")
    
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
                await cli.registry_block(args.package_name, args.ecosystem, args.version)
                
        elif args.command == "logs":
            if args.logs_action == "view":
                await cli.view_logs(args.limit)
            elif args.logs_action == "packages":
                await cli.view_malicious_packages(args.limit, args.ecosystem, args.hours)
                
        elif args.command == "feed":
            if args.feed_action == "fetch":
                await cli.fetch_feed_packages(args.ecosystem, args.limit, args.hours)
                
        elif args.command == "scan":
            if args.scan_action == "crossref":
                await cli.security_crossref(args.hours, args.ecosystem, args.limit, args.no_report)
            elif args.scan_action == "test":
                await cli.security_crossref_test(args.ecosystem)
            elif args.scan_action == "run":
                await cli.run_manual_scan()
                
        elif args.command == "health":
            if args.health_action == "check":
                await cli.health_check()
                
        elif args.command == "test":
            if args.test_action == "create":
                await cli.create_test_data()
            elif args.test_action == "cleanup":
                await cli.cleanup_test_data()
                
        elif args.command == "interactive":
            interactive = InteractiveCLI(cli)
            interactive.cmdloop()
    
    except KeyboardInterrupt:
        cli.console.print("\n👋 Goodbye!", style="blue")
    except Exception as e:
        cli.console.print(f"❌ Fatal error: {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())