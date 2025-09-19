"""JFrog Artifactory registry provider."""

import asyncio
import logging
import base64
from typing import List, Dict, Any, Optional
import aiohttp
from aiohttp import ClientTimeout

from ...core.interfaces import PackagesRegistryService
from ...core.entities import MaliciousPackage
from ..exceptions import RegistryError


logger = logging.getLogger(__name__)


class JFrogRegistry(PackagesRegistryService):
    """JFrog Artifactory registry provider."""
    
    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0
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
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.api_key = api_key
        self.timeout = ClientTimeout(total=timeout_seconds)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Validate authentication
        if not api_key and not (username and password):
            raise ValueError("Either api_key or username/password must be provided")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with authentication headers."""
        if self._session is None or self._session.closed:
            headers = self._get_auth_headers()
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=headers
            )
        return self._session
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for JFrog API."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if self.api_key:
            # Use Bearer token for JWT-based API keys
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.username and self.password:
            # Basic authentication
            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        
        return headers
    
    async def block_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Block malicious packages in JFrog Artifactory.
        
        Args:
            packages: List of malicious packages to block
            
        Returns:
            List of package identifiers that were successfully blocked
            
        Raises:
            RegistryError: If blocking operation fails
        """
        logger.info(f"Blocking {len(packages)} packages in JFrog Artifactory")
        
        blocked_packages = []
        
        for package in packages:
            try:
                success = await self._block_single_package(package)
                if success:
                    blocked_packages.append(package.package_identifier)
                    logger.debug(f"Successfully blocked package: {package.package_identifier}")
                else:
                    logger.warning(f"Failed to block package: {package.package_identifier}")
            
            except Exception as e:
                logger.error(f"Error blocking package {package.package_identifier}: {e}")
                # Continue with other packages
        
        logger.info(f"Successfully blocked {len(blocked_packages)} out of {len(packages)} packages")
        return blocked_packages
    
    async def block_package(self, package: MaliciousPackage) -> bool:
        """
        Block a single malicious package in the registry.
        
        Args:
            package: Malicious package to block
            
        Returns:
            True if successfully blocked, False otherwise
            
        Raises:
            RegistryError: If blocking operation fails
        """
        logger.info(f"Blocking package: {package.package_identifier}")
        
        try:
            success = await self._block_single_package(package)
            if success:
                logger.info(f"Successfully blocked package: {package.package_identifier}")
            else:
                logger.warning(f"Failed to block package: {package.package_identifier}")
            return success
        except Exception as e:
            logger.error(f"Error blocking package {package.package_identifier}: {e}")
            raise RegistryError(f"Failed to block package {package.package_identifier}: {e}") from e
    
    async def _block_single_package(self, package: MaliciousPackage) -> bool:
        """Block a single package in JFrog Artifactory."""
        session = await self._get_session()
        
        # Get repository name based on ecosystem
        repo_name = self._get_repository_name(package.ecosystem)
        if not repo_name:
            logger.warning(f"No repository mapping for ecosystem: {package.ecosystem}")
            return False
        
        # JFrog Artifactory API endpoint for setting properties
        # We'll use properties to mark packages as blocked
        package_path = self._get_package_path(package)
        properties_url = f"{self.base_url}/artifactory/api/storage/{repo_name}/{package_path}"
        
        # Set properties to mark as malicious/blocked
        properties = {
            "properties": {
                "security.malicious": ["true"],
                "security.blocked": ["true"],
                "security.reason": [f"Malicious package identified by security scanner"],
                "security.advisory_id": [package.advisory_id or "unknown"],
                "security.blocked_date": [str(asyncio.get_event_loop().time())]
            }
        }
        
        for attempt in range(self.max_retries + 1):
            try:
                # First, check if package exists
                async with session.get(properties_url) as response:
                    if response.status == 404:
                        # Package doesn't exist in repository, create a placeholder block
                        return await self._create_block_entry(session, repo_name, package)
                    elif response.status != 200:
                        logger.warning(f"Cannot access package {package.package_identifier}: HTTP {response.status}")
                        return False
                
                # Set blocking properties
                async with session.put(f"{properties_url}?properties={self._format_properties(properties)}"): 
                    if response.status in [200, 201]:
                        return True
                    elif response.status == 429:  # Rate limited
                        if attempt < self.max_retries:
                            await asyncio.sleep(self.retry_delay * (2 ** attempt))
                            continue
                        return False
                    else:
                        logger.warning(f"Failed to block package: HTTP {response.status}")
                        return False
            
            except aiohttp.ClientError as e:
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    continue
                logger.error(f"Network error blocking package: {e}")
                return False
        
        return False
    
    async def _create_block_entry(self, session: aiohttp.ClientSession, repo_name: str, package: MaliciousPackage) -> bool:
        """Create a block entry for a package that doesn't exist in the repository."""
        # Create a marker file to indicate the package is blocked
        marker_path = f"{self._get_package_path(package)}/.blocked"
        upload_url = f"{self.base_url}/artifactory/{repo_name}/{marker_path}"
        
        block_info = {
            "blocked": True,
            "reason": "Malicious package identified by security scanner",
            "advisory_id": package.advisory_id,
            "package_name": package.name,
            "ecosystem": package.ecosystem
        }
        
        try:
            async with session.put(upload_url, json=block_info) as response:
                return response.status in [200, 201]
        except Exception as e:
            logger.error(f"Failed to create block entry: {e}")
            return False
    
    def _format_properties(self, properties: Dict[str, Any]) -> str:
        """Format properties for JFrog API."""
        # Convert properties dict to query string format
        prop_parts = []
        for key, values in properties["properties"].items():
            for value in values:
                prop_parts.append(f"{key}={value}")
        return ";".join(prop_parts)
    
    async def check_existing_packages(self, packages: List[MaliciousPackage]) -> List[MaliciousPackage]:
        """
        Check which packages are already present/blocked in JFrog Artifactory.
        
        Args:
            packages: List of packages to check
            
        Returns:
            List of packages that are already present in the registry
        """
        logger.info(f"Checking {len(packages)} packages in JFrog Artifactory")
        
        existing_packages = []
        
        for package in packages:
            try:
                is_existing = await self._check_single_package(package)
                if is_existing:
                    existing_packages.append(package)
                    logger.debug(f"Package already exists: {package.package_identifier}")
            
            except Exception as e:
                logger.error(f"Error checking package {package.package_identifier}: {e}")
                # Continue with other packages
        
        logger.info(f"Found {len(existing_packages)} existing packages out of {len(packages)}")
        return existing_packages
    
    async def _check_single_package(self, package: MaliciousPackage) -> bool:
        """Check if a single package exists or is blocked in JFrog Artifactory."""
        session = await self._get_session()
        
        repo_name = self._get_repository_name(package.ecosystem)
        if not repo_name:
            return False
        
        package_path = self._get_package_path(package)
        
        # Check for actual package or block marker
        urls_to_check = [
            f"{self.base_url}/artifactory/api/storage/{repo_name}/{package_path}",
            f"{self.base_url}/artifactory/api/storage/{repo_name}/{package_path}/.blocked"
        ]
        
        for url in urls_to_check:
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        # Check if it's marked as blocked
                        if "blocked" in url:
                            return True
                        
                        # Check properties for blocking status
                        data = await response.json()
                        properties = data.get("properties", {})
                        if properties.get("security.blocked") == ["true"]:
                            return True
                        
                        return True  # Package exists
            
            except Exception:
                continue
        
        return False
    
    async def unblock_packages(self, packages: List[MaliciousPackage]) -> List[str]:
        """
        Unblock packages in JFrog Artifactory.
        
        Args:
            packages: List of packages to unblock
            
        Returns:
            List of package identifiers that were successfully unblocked
        """
        logger.info(f"Unblocking {len(packages)} packages in JFrog Artifactory")
        
        unblocked_packages = []
        
        for package in packages:
            try:
                success = await self._unblock_single_package(package)
                if success:
                    unblocked_packages.append(package.package_identifier)
                    logger.debug(f"Successfully unblocked package: {package.package_identifier}")
            
            except Exception as e:
                logger.error(f"Error unblocking package {package.package_identifier}: {e}")
        
        logger.info(f"Successfully unblocked {len(unblocked_packages)} packages")
        return unblocked_packages
    
    async def _unblock_single_package(self, package: MaliciousPackage) -> bool:
        """Unblock a single package in JFrog Artifactory."""
        session = await self._get_session()
        
        repo_name = self._get_repository_name(package.ecosystem)
        if not repo_name:
            return False
        
        package_path = self._get_package_path(package)
        
        # Remove blocking properties
        properties_url = f"{self.base_url}/artifactory/api/storage/{repo_name}/{package_path}"
        properties_to_remove = [
            "security.malicious",
            "security.blocked", 
            "security.reason",
            "security.advisory_id",
            "security.blocked_date"
        ]
        
        try:
            for prop in properties_to_remove:
                async with session.delete(f"{properties_url}?properties={prop}") as response:
                    # Continue even if some properties don't exist
                    pass
            
            # Remove block marker file if it exists
            marker_url = f"{self.base_url}/artifactory/{repo_name}/{package_path}/.blocked"
            async with session.delete(marker_url) as response:
                # Ignore errors - marker might not exist
                pass
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to unblock package: {e}")
            return False
    
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
            "crates.io": "cargo-remote"
        }
        return ecosystem_mapping.get(ecosystem)
    
    def _get_package_path(self, package: MaliciousPackage) -> str:
        """Get package path for ecosystem."""
        if package.ecosystem == "PyPI":
            # PyPI path format: simple/package-name/
            return f"simple/{package.name.lower()}/"
        elif package.ecosystem == "npm":
            # npm path format: package-name or @scope/package-name  
            return package.name
        elif package.ecosystem == "Maven":
            # Maven path format: group/artifact/version
            # For simplicity, use package name as artifact
            parts = package.name.split(":")
            if len(parts) >= 2:
                return f"{parts[0].replace('.', '/')}/{parts[1]}"
            else:
                return package.name.replace(".", "/")
        else:
            # Generic path
            return package.name
    
    async def is_package_blocked(self, package: MaliciousPackage) -> bool:
        """Check if a package is blocked in JFrog Artifactory."""
        return await self._check_single_package(package)
    
    async def search_packages(self, package_name: str, ecosystem: str) -> List[Dict[str, Any]]:
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
            repo_name = self._get_repository_name(ecosystem)
            
            if not repo_name:
                logger.warning(f"No repository mapping for ecosystem: {ecosystem}")
                return []
            
            # Use AQL (Artifactory Query Language) for search
            # Be very specific - search for the exact package directory
            if ecosystem.lower() == "npm":
                # Search for files in the specific package directory
                aql_query = f'''items.find({{"path": {{"$match": ".npm/{package_name}*"}}}})'''
            else:
                # For other ecosystems, search primarily by name
                aql_query = f'''items.find({{
                    "repo": "{repo_name}",
                    "name": {{"$match": "*{package_name}*"}}
                }})'''
            
            search_url = f"{self.base_url}/artifactory/api/search/aql"
            
            logger.info(f"Searching packages with AQL: {search_url}")
            logger.info(f"AQL query: {aql_query}")
            
            # AQL queries are sent as plain text in POST body with text/plain content-type
            headers = {"Content-Type": "text/plain"}
            async with session.post(search_url, data=aql_query, headers=headers) as response:
                logger.info(f"AQL search response status: {response.status}")
                
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"AQL search response: {data}")
                    
                    results = data.get("results", [])
                    
                    # Process and format results
                    formatted_results = []
                    version_files = []
                    package_json_files = []
                    
                    for item in results:
                        # Extract version from filename or path for npm packages
                        version = ""
                        name = item.get("name", "")
                        path = item.get("path", "")
                        
                        if ecosystem.lower() == "npm":
                            # npm packages often have version files like: package-name-version.json
                            import re
                            version_patterns = [
                                rf'{re.escape(package_name)}-([0-9]+\.[0-9]+\.[0-9]+[^.]*)\.json',  # package-version.json
                                r'([0-9]+\.[0-9]+\.[0-9]+[^/]*)',  # any semantic version
                            ]
                            for pattern in version_patterns:
                                match = re.search(pattern, name)
                                if match:
                                    version = match.group(1)
                                    break
                        
                        result_item = {
                            "name": name,
                            "path": path,
                            "repo": item.get("repo", ""),
                            "type": item.get("type", ""),
                            "size": item.get("size", 0),
                            "created": item.get("created", ""),
                            "modified": item.get("modified", ""),
                            "sha1": item.get("actual_sha1", ""),
                            "sha256": item.get("sha256", ""),
                            "version": version
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
                    
                    logger.info(f"Found {len(formatted_results)} packages matching '{package_name}' in {ecosystem}")
                    return formatted_results
                else:
                    error_text = await response.text()
                    logger.error(f"AQL search failed: {response.status} - {error_text}")
                    return []
                    
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
                    logger.error(f"Health check failed: {response.status} - {response_text}")
                    await simple_session.close()
                    return False
        except Exception as e:
            logger.error(f"Health check exception: {e}")
            return False
    
    def get_registry_name(self) -> str:
        """
        Get the display name of the registry.
        
        Returns:
            Human-readable name of the registry
        """
        return "JFrog Artifactory"
    
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