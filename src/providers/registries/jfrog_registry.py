"""JFrog Artifactory registry provider using exclusion patterns."""

import asyncio
import base64
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp import ClientTimeout

from ...core.entities import MaliciousPackage
from ...core.interfaces import PackagesRegistryService
from ..exceptions import RegistryError

logger = logging.getLogger(__name__)


class JFrogRegistry(PackagesRegistryService):
    """JFrog Artifactory registry provider using exclusion patterns for prevention."""

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        repository_overrides: Optional[Dict[str, str]] = None,
        cache_ttl_seconds: int = 3600,
    ):
        """
        Initialize JFrog registry provider.

        Args:
            base_url: JFrog Artifactory base URL
            username: Username for authentication
            password: Password for authentication
            api_key: API key for authentication (alternative to username/password)
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            repository_overrides: Manual repository name overrides by ecosystem
            cache_ttl_seconds: Cache TTL for repository discovery
        """
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.timeout = ClientTimeout(total=timeout_seconds)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.repository_overrides = repository_overrides or {}
        self.cache_ttl_seconds = cache_ttl_seconds
        self._session: Optional[aiohttp.ClientSession] = None
        self._repository_cache: Dict[str, List[str]] = {}
        self._cache_timestamps: Dict[str, float] = {}

        # Validate authentication
        if not api_key and not (username and password):
            raise ValueError("Either api_key or username/password must be provided")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with authentication headers."""
        if self._session is None or self._session.closed:
            headers = self._get_auth_headers()
            self._session = aiohttp.ClientSession(timeout=self.timeout, headers=headers)
        return self._session

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for JFrog API."""
        headers = {
            "Content-Type": "application/json"
            # Note: Don't set Accept header for repository updates - causes 406 errors
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.username and self.password:
            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Block malicious packages using exclusion patterns.

        Args:
            packages: List of malicious packages to block

        Returns:
            List of package identifiers that were successfully blocked

        Raises:
            RegistryError: If blocking operation fails
        """
        logger.info(f"Blocking {len(packages)} packages using exclusion patterns")

        # Group packages by ecosystem for batch processing
        packages_by_ecosystem = self._group_packages_by_ecosystem(packages)
        blocked_packages = []

        for ecosystem, ecosystem_packages in packages_by_ecosystem.items():
            try:
                repos = await self.discover_repositories_by_ecosystem(ecosystem)
                if not repos:
                    logger.warning(f"No repositories found for ecosystem: {ecosystem}")
                    continue

                # Apply exclusion patterns to all relevant repositories
                for repo_name in repos:
                    success_count = await self._add_exclusion_patterns(
                        repo_name, ecosystem_packages
                    )
                    if success_count > 0:
                        blocked_packages.extend(
                            [
                                pkg.package_identifier
                                for pkg in ecosystem_packages[:success_count]
                            ]
                        )

            except Exception as e:
                logger.error(f"Failed to block packages for ecosystem {ecosystem}: {e}")
                raise RegistryError(
                    f"Failed to block packages for ecosystem {ecosystem}"
                ) from e

        logger.info(
            f"Successfully blocked {len(blocked_packages)} out of {len(packages)} packages"
        )
        return blocked_packages

    async def block_package(self, package: MaliciousPackage) -> bool:
        """
        Block a single malicious package using exclusion patterns.

        Args:
            package: Malicious package to block

        Returns:
            True if successfully blocked, False otherwise

        Raises:
            RegistryError: If blocking operation fails
        """
        logger.info(f"Blocking package: {package.package_identifier}")

        try:
            repos = await self.discover_repositories_by_ecosystem(package.ecosystem)
            if not repos:
                logger.warning(
                    f"No repositories found for ecosystem: {package.ecosystem}"
                )
                return False

            # Apply exclusion pattern to all relevant repositories
            blocked_any = False
            for repo_name in repos:
                success = await self._add_exclusion_patterns(repo_name, [package])
                if success > 0:
                    blocked_any = True

            return blocked_any

        except Exception as e:
            logger.error(f"Failed to block package {package.package_identifier}: {e}")
            raise RegistryError(
                f"Failed to block package {package.package_identifier}"
            ) from e

    async def discover_repositories_by_ecosystem(self, ecosystem: str) -> List[str]:
        """
        Discover repository names for a given ecosystem.

        Args:
            ecosystem: Package ecosystem (npm, PyPI, etc.)

        Returns:
            List of repository names that handle this ecosystem
        """
        # Check for manual override first
        if ecosystem in self.repository_overrides:
            override_repo = self.repository_overrides[ecosystem]
            logger.info(
                f"Using configured repository override for {ecosystem}: {override_repo}"
            )
            return [override_repo]

        # Check cache with TTL
        current_time = asyncio.get_event_loop().time()
        if ecosystem in self._repository_cache:
            cache_time = self._cache_timestamps.get(ecosystem, 0)
            if current_time - cache_time < self.cache_ttl_seconds:
                return self._repository_cache[ecosystem]

        session = await self._get_session()
        matching_repos = []

        # Try the API endpoint first
        repos_url = f"{self.base_url}/artifactory/api/repositories"
        try:
            async with session.get(repos_url) as response:
                if response.status == 200:
                    repositories = await response.json()

                    for repo in repositories:
                        repo_type = repo.get("packageType", "").lower()
                        repo_class = repo.get("rclass", "")

                        if self._ecosystem_matches_package_type(ecosystem, repo_type):
                            # Include all repository types for exclusion patterns
                            matching_repos.append(repo["key"])
                            logger.info(
                                f"Found {ecosystem} repository: {repo['key']} ({repo_class})"
                            )
                else:
                    logger.warning(
                        f"Repository API returned status {response.status}, falling back to AQL search"
                    )

        except Exception as e:
            logger.warning(f"Repository API failed: {e}, falling back to AQL search")

        # If no repositories found via API, try AQL-based discovery
        if not matching_repos:
            logger.info(
                f"No repositories found via API for {ecosystem}, trying AQL-based discovery"
            )
            matching_repos = await self._discover_repositories_via_aql(
                ecosystem, session
            )

        # Update cache
        self._repository_cache[ecosystem] = matching_repos
        self._cache_timestamps[ecosystem] = current_time
        return matching_repos

    async def _discover_repositories_via_aql(
        self, ecosystem: str, session: aiohttp.ClientSession
    ) -> List[str]:
        """
        Discover repositories containing packages for an ecosystem using AQL queries.

        Args:
            ecosystem: Package ecosystem (npm, PyPI, etc.)
            session: aiohttp session

        Returns:
            List of repository names that contain packages for this ecosystem
        """
        search_url = f"{self.base_url}/artifactory/api/search/aql"
        headers = {"Content-Type": "text/plain"}

        # Define ecosystem-specific search patterns (using regex for AQL $match)
        ecosystem_patterns = {
            "npm": ".*\\.tgz",
            "PyPI": ".*\\.whl",
            "Maven": ".*\\.jar",
            "Go": ".*\\.mod",
            "NuGet": ".*\\.nupkg",
            "RubyGems": ".*\\.gem",
            "crates.io": ".*\\.crate",
            "Packagist": "composer.json",
        }

        pattern = ecosystem_patterns.get(
            ecosystem, ".*\\.tgz"
        )  # Default to npm pattern

        # Search for files matching the ecosystem pattern across all repositories
        aql_query = f'items.find({{"name": {{"$match": "{pattern}"}}}}).include("repo", "path", "name").limit(100)'

        try:
            async with session.post(
                search_url, data=aql_query, headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get("results", [])

                    # Extract unique repository names
                    repo_names = list(
                        set(item.get("repo") for item in results if item.get("repo"))
                    )

                    logger.info(
                        f"Found {len(repo_names)} repositories containing {ecosystem} packages via AQL: {repo_names}"
                    )
                    return repo_names
                else:
                    response_text = await response.text()
                    logger.error(
                        f"AQL discovery failed for {ecosystem} with status: {response.status}, response: {response_text[:200]}..."
                    )
                    return []

        except Exception as e:
            logger.error(
                f"Error in AQL-based repository discovery for {ecosystem}: {e}"
            )
            return []

    def _ecosystem_matches_package_type(
        self, ecosystem: str, package_type: str
    ) -> bool:
        """Map OSV ecosystems to Artifactory package types."""
        ecosystem_to_package_type = {
            "npm": "npm",
            "PyPI": "pypi",
            "Maven": "maven",
            "Go": "go",
            "NuGet": "nuget",
            "RubyGems": "gems",
            "crates.io": "cargo",
            "Packagist": "composer",
            "Pub": "generic",  # Dart/Flutter packages often stored as generic
            "Hex": "generic",  # Elixir packages often stored as generic
        }

        expected_type = ecosystem_to_package_type.get(ecosystem, "").lower()
        return package_type == expected_type

    async def get_supported_ecosystems(self) -> List[str]:
        """
        Get list of ecosystems supported by this registry.

        Returns:
            List of ecosystem names that this registry can handle
        """
        return [
            "npm",
            "PyPI",
            "Maven",
            "Go",
            "NuGet",
            "RubyGems",
            "crates.io",
            "Packagist",
            "Pub",
            "Hex",
        ]

    def get_ecosystem_blocking_support(self, ecosystem: str) -> Dict[str, bool]:
        """
        Get blocking support information for an ecosystem.

        Args:
            ecosystem: Ecosystem name

        Returns:
            Dictionary with scanning and blocking support flags
        """
        # Ecosystems with full exclusion pattern support
        full_support = {"npm", "PyPI", "Maven", "Go", "NuGet"}

        # Ecosystems with basic exclusion pattern support
        basic_support = {"RubyGems", "crates.io", "Packagist"}

        # Ecosystems with scanning but limited blocking support
        limited_support = {"Pub", "Hex"}

        if ecosystem in full_support:
            return {"scanning": True, "blocking": True, "pattern_quality": "full"}
        elif ecosystem in basic_support:
            return {"scanning": True, "blocking": True, "pattern_quality": "basic"}
        elif ecosystem in limited_support:
            return {"scanning": True, "blocking": False, "pattern_quality": "none"}
        else:
            return {"scanning": False, "blocking": False, "pattern_quality": "none"}

    async def _add_exclusion_patterns(
        self, repo_name: str, packages: List[MaliciousPackage]
    ) -> int:
        """
        Add exclusion patterns for malicious packages to a repository.

        Args:
            repo_name: Repository name
            packages: List of packages to add exclusion patterns for

        Returns:
            Number of packages successfully added to exclusion patterns
        """
        session = await self._get_session()
        repo_config_url = f"{self.base_url}/artifactory/api/repositories/{repo_name}"

        for attempt in range(self.max_retries + 1):
            try:
                # Get current repository configuration
                async with session.get(repo_config_url) as response:
                    if response.status != 200:
                        logger.error(
                            f"Failed to get repository config for {repo_name}: {response.status}"
                        )
                        if attempt < self.max_retries:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        return 0

                    repo_config = await response.json()

                # Generate exclusion patterns for packages
                new_patterns = []
                for package in packages:
                    pattern = self._generate_exclusion_pattern(package)
                    if pattern:
                        new_patterns.append(pattern)
                        logger.info(
                            f"Generated exclusion pattern for {package.package_identifier}: {pattern}"
                        )

                if not new_patterns:
                    logger.warning(
                        f"No valid exclusion patterns generated for {len(packages)} packages"
                    )
                    return 0

                # Update excludes pattern in repository configuration
                current_excludes = repo_config.get("excludesPattern", "")
                all_patterns = self._merge_exclusion_patterns(
                    current_excludes, new_patterns
                )

                # Send only the changed field instead of the entire config
                update_payload = {"excludesPattern": all_patterns}

                # Update repository configuration with both pattern and metadata
                async with session.post(
                    repo_config_url, json=update_payload
                ) as update_response:
                    if update_response.status in [200, 201]:
                        logger.info(
                            f"Updated exclusion patterns for repository {repo_name}"
                        )

                        return len(new_patterns)
                    else:
                        response_text = await update_response.text()
                        logger.error(
                            f"Failed to update repository config: {update_response.status} - {response_text}"
                        )
                        logger.error(f"Request payload: {update_payload}")
                        if attempt < self.max_retries:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        return 0

            except Exception as e:
                logger.error(
                    f"Error updating exclusion patterns (attempt {attempt + 1}): {e}"
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    continue
                return 0

        return 0

    def _generate_exclusion_pattern(self, package: MaliciousPackage) -> Optional[str]:
        """
        Generate an exclusion pattern for a malicious package.

        Args:
            package: Malicious package to generate pattern for

        Returns:
            Exclusion pattern string or None if not supported
        """
        # Generate the base pattern
        base_pattern = None

        if package.ecosystem == "npm":
            # NPM exclusion patterns
            if "/" in package.name:  # Scoped package like @scope/package
                if package.version:
                    base_pattern = f"{package.name}/-/{package.name.split('/')[-1]}-{package.version}.tgz"
                else:
                    base_pattern = f"{package.name}/**"
            else:
                if package.version:
                    base_pattern = (
                        f"{package.name}/-/{package.name}-{package.version}.tgz"
                    )
                else:
                    base_pattern = f"{package.name}/**"

        elif package.ecosystem == "PyPI":
            # PyPI exclusion patterns
            normalized_name = package.name.lower().replace("_", "-")
            if package.version:
                # Block specific version with common file extensions
                base_pattern = (
                    f"simple/{normalized_name}/{normalized_name}-{package.version}*"
                )
            else:
                # Block all versions of the package
                base_pattern = f"simple/{normalized_name}/**"

        elif package.ecosystem == "Maven":
            # Maven GAV exclusion patterns
            if ":" in package.name:
                parts = package.name.split(":")
                group_id = parts[0].replace(".", "/")
                artifact_id = parts[1] if len(parts) > 1 else "*"
                if package.version and len(parts) > 2:
                    version = parts[2]
                    base_pattern = f"{group_id}/{artifact_id}/{version}/**"
                elif package.version:
                    base_pattern = f"{group_id}/{artifact_id}/{package.version}/**"
                else:
                    base_pattern = f"{group_id}/{artifact_id}/**"
            else:
                base_pattern = f"**/{package.name}/**"

        elif package.ecosystem == "Go":
            # Go module exclusion patterns
            if package.version:
                base_pattern = f"{package.name}/@v/{package.version}*"
            else:
                base_pattern = f"{package.name}/**"

        elif package.ecosystem == "NuGet":
            # NuGet exclusion patterns
            if package.version:
                base_pattern = f"{package.name.lower()}/{package.version}/**"
            else:
                base_pattern = f"{package.name.lower()}/**"

        elif package.ecosystem == "RubyGems":
            # RubyGems exclusion patterns
            if package.version:
                base_pattern = f"gems/{package.name}-{package.version}.gem"
            else:
                base_pattern = f"gems/{package.name}-*.gem"

        elif package.ecosystem == "crates.io":
            # Rust crates exclusion patterns
            if package.version:
                base_pattern = (
                    f"crates/{package.name}/{package.name}-{package.version}.crate"
                )
            else:
                base_pattern = f"crates/{package.name}/**"

        elif package.ecosystem == "Packagist":
            # PHP Composer exclusion patterns
            if "/" in package.name:  # vendor/package format
                if package.version:
                    base_pattern = f"{package.name}/{package.version}/**"
                else:
                    base_pattern = f"{package.name}/**"
            else:
                if package.version:
                    base_pattern = f"**/{package.name}/{package.version}/**"
                else:
                    base_pattern = f"**/{package.name}/**"

        elif package.ecosystem == "Pub":
            # Dart/Flutter packages (often stored as generic artifacts)
            logger.warning(
                f"Pub/Dart ecosystem has limited blocking support for package: {package.name}"
            )
            if package.version:
                base_pattern = f"**/{package.name}-{package.version}*"
            else:
                base_pattern = f"**/{package.name}*"

        elif package.ecosystem == "Hex":
            # Elixir packages (often stored as generic artifacts)
            logger.warning(
                f"Hex/Elixir ecosystem has limited blocking support for package: {package.name}"
            )
            if package.version:
                base_pattern = f"**/{package.name}-{package.version}*"
            else:
                base_pattern = f"**/{package.name}*"

        else:
            # Generic pattern for unsupported ecosystems
            logger.warning(
                f"Unsupported ecosystem for exclusion pattern: {package.ecosystem}"
            )
            if package.version:
                base_pattern = f"**/{package.name}/{package.version}/**"
            else:
                base_pattern = f"**/{package.name}/**"

        # Add Malifiscan identifier to the pattern (as a comment-like suffix)
        # Note: JFrog doesn't support actual comments in patterns, but we can add a descriptive suffix
        if base_pattern:
            # We'll add this as metadata in a different way since patterns don't support comments
            return base_pattern

        return None

    def _merge_exclusion_patterns(
        self, current_patterns: str, new_patterns: List[str]
    ) -> str:
        """
        Merge new exclusion patterns with existing ones.

        Args:
            current_patterns: Current exclusion patterns (comma-separated)
            new_patterns: New patterns to add

        Returns:
            Merged patterns string
        """
        if not current_patterns:
            return ",".join(new_patterns)

        # Split current patterns and remove duplicates
        existing = set(p.strip() for p in current_patterns.split(",") if p.strip())
        new_set = set(new_patterns)

        # Combine and avoid duplicates
        all_patterns = existing.union(new_set)
        return ",".join(sorted(all_patterns))

    def _group_packages_by_ecosystem(
        self, packages: List[MaliciousPackage]
    ) -> Dict[str, List[MaliciousPackage]]:
        """Group packages by ecosystem for batch processing."""
        groups: Dict[str, List[MaliciousPackage]] = {}
        for package in packages:
            if package.ecosystem not in groups:
                groups[package.ecosystem] = []
            groups[package.ecosystem].append(package)
        return groups

    async def check_existing_packages(
        self, packages: List[MaliciousPackage]
    ) -> List[MaliciousPackage]:
        """
        Check which packages are affected by current exclusion patterns.

        Args:
            packages: List of packages to check

        Returns:
            List of packages that would be blocked by exclusion patterns
        """
        logger.info(f"Checking exclusion patterns for {len(packages)} packages")

        blocked_packages = []
        packages_by_ecosystem = self._group_packages_by_ecosystem(packages)

        for ecosystem, ecosystem_packages in packages_by_ecosystem.items():
            repos = await self.discover_repositories_by_ecosystem(ecosystem)

            for repo_name in repos:
                excluded_in_repo = await self._check_exclusion_patterns(
                    repo_name, ecosystem_packages
                )
                blocked_packages.extend(excluded_in_repo)

        # Remove duplicates while preserving order
        seen = set()
        unique_blocked = []
        for pkg in blocked_packages:
            if pkg.package_identifier not in seen:
                seen.add(pkg.package_identifier)
                unique_blocked.append(pkg)

        logger.info(
            f"Found {len(unique_blocked)} packages affected by exclusion patterns"
        )
        return unique_blocked

    async def _check_exclusion_patterns(
        self, repo_name: str, packages: List[MaliciousPackage]
    ) -> List[MaliciousPackage]:
        """Check which packages are blocked by repository exclusion patterns."""
        session = await self._get_session()
        repo_config_url = f"{self.base_url}/artifactory/api/repositories/{repo_name}"

        try:
            async with session.get(repo_config_url) as response:
                if response.status != 200:
                    return []

                repo_config = await response.json()
                excludes_pattern = repo_config.get("excludesPattern", "")

                if not excludes_pattern:
                    return []

                # Check which packages match the exclusion patterns
                blocked_packages = []
                for package in packages:
                    package_pattern = self._generate_exclusion_pattern(package)
                    if package_pattern and package_pattern in excludes_pattern:
                        blocked_packages.append(package)

                return blocked_packages

        except Exception as e:
            logger.error(f"Error checking exclusion patterns for {repo_name}: {e}")
            return []

    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Remove packages from exclusion patterns.

        Args:
            packages: List of packages to unblock

        Returns:
            List of package identifiers that were successfully unblocked
        """
        logger.info(f"Unblocking {len(packages)} packages from exclusion patterns")

        packages_by_ecosystem = self._group_packages_by_ecosystem(packages)
        unblocked_packages = []

        for ecosystem, ecosystem_packages in packages_by_ecosystem.items():
            repos = await self.discover_repositories_by_ecosystem(ecosystem)

            for repo_name in repos:
                success_count = await self._remove_exclusion_patterns(
                    repo_name, ecosystem_packages
                )
                if success_count > 0:
                    unblocked_packages.extend(
                        [
                            pkg.package_identifier
                            for pkg in ecosystem_packages[:success_count]
                        ]
                    )

        logger.info(f"Successfully unblocked {len(unblocked_packages)} packages")
        return unblocked_packages

    async def _remove_exclusion_patterns(
        self, repo_name: str, packages: List[MaliciousPackage]
    ) -> int:
        """Remove exclusion patterns for packages from repository configuration."""
        session = await self._get_session()
        repo_config_url = f"{self.base_url}/artifactory/api/repositories/{repo_name}"

        try:
            # Get current repository configuration
            async with session.get(repo_config_url) as response:
                if response.status != 200:
                    return 0

                repo_config = await response.json()

            # Generate patterns to remove
            patterns_to_remove = []
            for package in packages:
                pattern = self._generate_exclusion_pattern(package)
                if pattern:
                    patterns_to_remove.append(pattern)

            if not patterns_to_remove:
                return 0

            # Remove patterns from exclusion list
            current_excludes = repo_config.get("excludesPattern", "")
            updated_excludes = self._remove_patterns_from_exclusions(
                current_excludes, patterns_to_remove
            )

            # Send only the changed field instead of the entire config
            update_payload = {"excludesPattern": updated_excludes}

            # Update repository configuration
            async with session.post(
                repo_config_url, json=update_payload
            ) as update_response:
                if update_response.status in [200, 201]:
                    logger.info(
                        f"Removed exclusion patterns from repository {repo_name}"
                    )
                    return len(patterns_to_remove)
                else:
                    logger.error(
                        f"Failed to update repository config: {update_response.status}"
                    )
                    return 0

        except Exception as e:
            logger.error(f"Error removing exclusion patterns: {e}")
            return 0

    def _remove_patterns_from_exclusions(
        self, current_patterns: str, patterns_to_remove: List[str]
    ) -> str:
        """Remove specific patterns from exclusion string."""
        if not current_patterns:
            return ""

        existing = [p.strip() for p in current_patterns.split(",") if p.strip()]
        remove_set = set(patterns_to_remove)

        # Filter out patterns to remove
        remaining = [p for p in existing if p not in remove_set]
        return ",".join(remaining)

    def _get_repository_name(self, ecosystem: str) -> Optional[str]:
        """Get JFrog repository name for ecosystem."""
        # This mapping should be configurable in a real implementation
        ecosystem_mapping = {
            "PyPI": "pypi-remote",
            "npm": "npm-remote",
            "Maven": "maven-remote",
            "Go": "go-remote",
            "NuGet": "nuget-remote",
            "RubyGems": "gems-remote",
            "crates.io": "cargo-remote",
            "Packagist": "composer-remote",
            "Pub": "generic-remote",
            "Hex": "generic-remote",
        }
        return ecosystem_mapping.get(ecosystem)

    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """
        Check if a package is blocked by exclusion patterns.

        Args:
            package: Package to check

        Returns:
            True if package is blocked, False otherwise
        """
        blocked_packages = await self.check_existing_packages([package])
        return len(blocked_packages) > 0

    def _extract_version_from_filename(
        self, filename: str, package_name: str, ecosystem: str
    ) -> str:
        """
        Extract version from package filename based on ecosystem-specific patterns.

        Args:
            filename: The filename to extract version from
            package_name: The package name being searched for
            ecosystem: The package ecosystem (npm, PyPI, etc.)

        Returns:
            Extracted version string, or empty string if no version found
        """
        if ecosystem.lower() == "npm":
            import re

            version_patterns = [
                # Match exact package name followed by version (for exact matches)
                rf"{re.escape(package_name)}-([0-9]+\.[0-9]+\.[0-9]+[^.]*)\.json",
                # Match any package name ending with searched name followed by version
                rf".*{re.escape(package_name)}.*?-([0-9]+\.[0-9]+\.[0-9]+[^.]*)\.json",
                # Match semantic version in filename, excluding .json suffix
                r"-([0-9]+\.[0-9]+\.[0-9]+[^./]*)\.json",
                # Fallback: any semantic version pattern but clean .json suffix
                r"([0-9]+\.[0-9]+\.[0-9]+[^/]*)",
            ]
            for pattern in version_patterns:
                match = re.search(pattern, filename)
                if match:
                    version = match.group(1)
                    # Clean any remaining .json suffix from version
                    if version.endswith(".json"):
                        version = version[:-5]
                    return version

        return ""

    def _is_npm_exact_match(self, item: Dict[str, Any], package_name: str) -> bool:
        """
        Validate that the npm search result is an exact match for the package name.

        Args:
            item: Search result item from AQL
            package_name: The exact npm package name we're searching for

        Returns:
            True if this is an exact match, False otherwise
        """
        path = item.get("path", "")

        if "/" in package_name:  # Scoped package like @scope/package
            expected_path = f".npm/{package_name}"
            return path == expected_path or path.startswith(f"{expected_path}/")
        else:
            # For regular npm packages, ensure exact directory match
            # Path should be exactly ".npm/{package_name}" or start with ".npm/{package_name}/"
            expected_path = f".npm/{package_name}"
            return path == expected_path or path.startswith(f"{expected_path}/")

    def _is_pypi_exact_match(self, item: Dict[str, Any], package_name: str) -> bool:
        """
        Validate that the PyPI search result is an exact match for the package name.

        Args:
            item: Search result item from AQL
            package_name: The exact PyPI package name we're searching for

        Returns:
            True if this is an exact match, False otherwise
        """
        path = item.get("path", "")
        # For PyPI, check normalized path
        normalized_name = package_name.lower().replace("_", "-")
        expected_path = f"simple/{normalized_name}"
        return path == expected_path or path.startswith(f"{expected_path}/")

    def _is_maven_exact_match(self, item: Dict[str, Any], package_name: str) -> bool:
        """
        Validate that the Maven search result is an exact match for the package name.

        Args:
            item: Search result item from AQL
            package_name: The exact Maven package identifier we're searching for

        Returns:
            True if this is an exact match, False otherwise
        """
        name = item.get("name", "")
        path = item.get("path", "")

        # For Maven, validate GAV structure
        if ":" in package_name:
            parts = package_name.split(":")
            group_path = parts[0].replace(".", "/")
            artifact_id = parts[1] if len(parts) > 1 else ""
            if artifact_id:
                expected_path = f"{group_path}/{artifact_id}"
                # Path should be exactly the expected path or start with expected_path/
                return path == expected_path or path.startswith(f"{expected_path}/")
        # For artifact-only, check exact name match
        return name == package_name

    def _is_generic_exact_match(self, item: Dict[str, Any], package_name: str) -> bool:
        """
        Validate that the generic search result is an exact match for the package name.

        Args:
            item: Search result item from AQL
            package_name: The exact package name we're searching for

        Returns:
            True if this is an exact match, False otherwise
        """
        name = item.get("name", "")
        return name == package_name

    def _build_npm_aql_query(self, package_name: str, repo_name: str) -> str:
        """
        Build AQL query for npm packages with exact matching.

        Args:
            package_name: The exact npm package name
            repo_name: Repository name

        Returns:
            AQL query string for exact npm package matching
        """
        if "/" in package_name:  # Scoped package like @scope/package
            # For scoped packages, we need to find both the directory and its contents
            # Use $or to search for exact path OR path with subdirectories
            return f"""items.find({{
                "repo": "{repo_name}",
                "$or": [
                    {{"path": {{"$eq": ".npm/{package_name}"}}}},
                    {{"path": {{"$match": ".npm/{package_name}/*"}}}}
                ]
            }})"""
        else:
            # For regular packages, we need to find both the directory and its contents
            # Use $or to search for exact path OR path with subdirectories
            return f"""items.find({{
                "repo": "{repo_name}",
                "$or": [
                    {{"path": {{"$eq": ".npm/{package_name}"}}}},
                    {{"path": {{"$match": ".npm/{package_name}/*"}}}}
                ]
            }})"""

    def _build_pypi_aql_query(self, package_name: str, repo_name: str) -> str:
        """
        Build AQL query for PyPI packages with exact matching.

        Args:
            package_name: The exact PyPI package name
            repo_name: Repository name

        Returns:
            AQL query string for exact PyPI package matching
        """
        # Normalize package name according to PEP 503
        normalized_name = package_name.lower().replace("_", "-")
        return f"""items.find({{
            "repo": "{repo_name}",
            "path": {{"$eq": "simple/{normalized_name}"}}
        }})"""

    def _build_maven_aql_query(self, package_name: str, repo_name: str) -> str:
        """
        Build AQL query for Maven packages with exact matching.

        Args:
            package_name: The exact Maven package identifier (group:artifact or just artifact)
            repo_name: Repository name

        Returns:
            AQL query string for exact Maven package matching
        """
        if ":" in package_name:
            # Handle full GAV coordinates (group:artifact:version)
            parts = package_name.split(":")
            group_path = parts[0].replace(".", "/")
            artifact_id = parts[1] if len(parts) > 1 else ""
            if artifact_id:
                return f"""items.find({{
                    "repo": "{repo_name}",
                    "path": {{"$eq": "{group_path}/{artifact_id}"}}
                }})"""
            else:
                return f"""items.find({{
                    "repo": "{repo_name}",
                    "path": {{"$eq": "{group_path}"}}
                }})"""
        else:
            # Fallback for artifact-only search
            return f"""items.find({{
                "repo": "{repo_name}",
                "name": {{"$eq": "{package_name}"}}
            }})"""

    def _build_generic_aql_query(self, package_name: str, repo_name: str) -> str:
        """
        Build AQL query for generic/other ecosystem packages with exact matching.

        Args:
            package_name: The exact package name
            repo_name: Repository name

        Returns:
            AQL query string for exact package name matching
        """
        return f"""items.find({{
            "repo": "{repo_name}",
            "name": {{"$eq": "{package_name}"}}
        }})"""

    async def search_packages(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """
        Search for packages in JFrog Artifactory using AQL.

        Args:
            package_name: Name of package to search for
            ecosystem: Package ecosystem (npm, PyPI, etc.)

        Returns:
            List of package information dictionaries
        """
        try:
            session = await self._get_session()

            repo_names = await self.discover_repositories_by_ecosystem(ecosystem)

            if not repo_names:
                logger.warning(f"No repositories found for ecosystem: {ecosystem}")
                return []

            # Search across all discovered repositories
            all_results = []

            for repo_name in repo_names:

                # Use AQL (Artifactory Query Language) for search
                # Use ecosystem-specific exact matching to avoid false positives
                ecosystem_lower = ecosystem.lower()
                if ecosystem_lower == "npm":
                    aql_query = self._build_npm_aql_query(package_name, repo_name)
                elif ecosystem_lower == "pypi":
                    aql_query = self._build_pypi_aql_query(package_name, repo_name)
                elif ecosystem_lower == "maven":
                    aql_query = self._build_maven_aql_query(package_name, repo_name)
                else:
                    aql_query = self._build_generic_aql_query(package_name, repo_name)

                search_url = f"{self.base_url}/artifactory/api/search/aql"

                logger.info(f"Searching packages with AQL in {repo_name}: {search_url}")
                logger.info(f"AQL query: {aql_query}")

                # AQL queries are sent as plain text in POST body with text/plain content-type
                headers = {"Content-Type": "text/plain"}

                async with session.post(
                    search_url, data=aql_query, headers=headers
                ) as response:
                    logger.info(
                        f"AQL search response status for {repo_name}: {response.status}"
                    )

                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"AQL search response for {repo_name}: {data}")

                        results = data.get("results", [])

                        # Add results from this repository to the overall results
                        all_results.extend(results)
                    else:
                        logger.warning(
                            f"Search failed for repository {repo_name} with status: {response.status}"
                        )

            # Process and format all results from all repositories
            formatted_results = []
            version_files = []
            package_json_files = []

            for item in all_results:
                # Validate that this is actually an exact match for our package
                ecosystem_lower = ecosystem.lower()
                is_exact_match = False

                if ecosystem_lower == "npm":
                    is_exact_match = self._is_npm_exact_match(item, package_name)
                elif ecosystem_lower == "pypi":
                    is_exact_match = self._is_pypi_exact_match(item, package_name)
                elif ecosystem_lower == "maven":
                    is_exact_match = self._is_maven_exact_match(item, package_name)
                else:
                    is_exact_match = self._is_generic_exact_match(item, package_name)

                if not is_exact_match:
                    continue

                # Extract version from filename or path for npm packages
                version = ""
                name = item.get("name", "")

                if ecosystem.lower() == "npm":
                    # Extract version using dedicated method
                    version = self._extract_version_from_filename(
                        name, package_name, ecosystem
                    )

                result_item = {
                    "name": name,
                    "path": item.get("path", ""),
                    "repo": item.get("repo", ""),
                    "type": item.get("type", ""),
                    "size": item.get("size", 0),
                    "created": item.get("created", ""),
                    "modified": item.get("modified", ""),
                    "sha1": item.get("actual_sha1", ""),
                    "sha256": item.get("sha256", ""),
                    "version": version,
                }

                # Prioritize version-specific files over generic package.json
                if version:
                    version_files.append(result_item)
                elif name == "package.json":
                    package_json_files.append(result_item)
                else:
                    formatted_results.append(result_item)

            # If we have version-specific files, use only those
            # Otherwise, fall back to package.json files
            if version_files:
                formatted_results = version_files + formatted_results
            else:
                formatted_results = package_json_files + formatted_results

            logger.info(
                f"Found {len(formatted_results)} packages matching '{package_name}' in {ecosystem}"
            )
            return formatted_results

        except Exception as e:
            logger.error(f"Error searching packages with AQL: {e}")
            return []

    async def health_check(self) -> bool:
        """Check if JFrog Artifactory is accessible."""
        try:
            # Create a simple session without auth headers for ping (ping doesn't require auth)
            simple_session = aiohttp.ClientSession(timeout=self.timeout)
            ping_url = f"{self.base_url}/artifactory/api/system/ping"
            logger.info(f"Health check: pinging {ping_url}")

            async with simple_session.get(ping_url) as response:
                logger.info(f"Health check response status: {response.status}")
                if response.status == 200:
                    response_text = await response.text()
                    logger.info(f"Health check response: {response_text}")
                    await simple_session.close()
                    return True
                else:
                    response_text = await response.text()
                    logger.error(
                        f"Health check failed: {response.status} - {response_text}"
                    )
                    await simple_session.close()
                    return False
        except Exception as e:
            logger.error(f"Health check exception: {e}")
            return False

    def get_registry_name(self) -> str:
        """Get the registry name for identification."""
        return "JFrog Artifactory"

    async def list_blocked_packages(self, ecosystem: str) -> List[Dict[str, Any]]:
        """
        List currently blocked packages by retrieving exclusion patterns.

        Args:
            ecosystem: Package ecosystem to filter by

        Returns:
            List of dictionaries containing pattern information
        """
        try:
            logger.info(f"Listing blocked packages for ecosystem: {ecosystem}")

            # Get repositories for this ecosystem
            repos = await self.discover_repositories_by_ecosystem(ecosystem)

            if not repos:
                logger.warning(f"No repositories found for ecosystem {ecosystem}")
                return []

            blocked_patterns = []
            session = await self._get_session()

            try:
                for repo_name in repos:
                    repo_config_url = (
                        f"{self.base_url}/artifactory/api/repositories/{repo_name}"
                    )

                    async with session.get(repo_config_url) as response:
                        if response.status == 200:
                            repo_config = await response.json()
                            excludes_pattern = repo_config.get("excludesPattern", "")

                            if excludes_pattern:
                                patterns = [
                                    p.strip()
                                    for p in excludes_pattern.split(",")
                                    if p.strip()
                                ]
                                for pattern in patterns:
                                    blocked_patterns.append(
                                        {
                                            "repository": repo_name,
                                            "pattern": pattern,
                                            "ecosystem": ecosystem,
                                        }
                                    )
                        else:
                            logger.warning(
                                f"Failed to get repository config for {repo_name}: {response.status}"
                            )

            finally:
                if session:
                    await session.close()

            logger.info(
                f"Found {len(blocked_patterns)} exclusion patterns for {ecosystem}"
            )
            return blocked_patterns

        except Exception as e:
            logger.error(f"Error listing blocked packages for {ecosystem}: {e}")
            raise

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
