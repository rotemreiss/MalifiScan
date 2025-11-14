"""OSV (Open Source Vulnerabilities) feed provider using GCS bucket."""

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from google.api_core import exceptions as gcs_exceptions
from google.cloud import storage

from ...core.cache import PackageCache
from ...core.entities import MaliciousPackage
from ...core.interfaces import PackagesFeed
from ..exceptions import FeedError

logger = logging.getLogger(__name__)


class OSVFeed(PackagesFeed):
    """OSV malicious packages feed provider using GCS bucket."""

    def __init__(
        self,
        bucket_name: str = "osv-vulnerabilities",
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        redis_url: Optional[str] = None,
    ):
        """
        Initialize OSV feed provider.

        Args:
            bucket_name: GCS bucket name containing OSV data
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            redis_url: Redis connection URL (e.g., redis://localhost:6379/0)
        """
        self.bucket_name = bucket_name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._client: Optional[storage.Client] = None
        self._bucket: Optional[storage.Bucket] = None
        self._cache = PackageCache(redis_url=redis_url)

    def _get_client(self) -> storage.Client:
        """Get or create GCS client."""
        if self._client is None:
            # Create anonymous client for public bucket access
            self._client = storage.Client.create_anonymous_client()
        return self._client

    def _get_bucket(self) -> storage.Bucket:
        """Get or create GCS bucket reference."""
        if self._bucket is None:
            client = self._get_client()
            self._bucket = client.bucket(self.bucket_name)
        return self._bucket

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics including hits/misses from last fetch
        """
        stats = self._cache.get_stats()
        # Add fetch-specific stats if available
        if hasattr(self, "_total_cache_hits"):
            stats["last_fetch_hits"] = self._total_cache_hits
            stats["last_fetch_misses"] = self._total_cache_misses
            if self._total_cache_hits + self._total_cache_misses > 0:
                total = self._total_cache_hits + self._total_cache_misses
                stats["last_fetch_hit_rate"] = (self._total_cache_hits / total) * 100
        return stats

    def purge_cache(self) -> int:
        """
        Purge all cached packages.

        Returns:
            Number of packages removed from cache
        """
        return self._cache.purge()

    async def fetch_malicious_packages(
        self,
        max_packages: Optional[int] = None,
        hours: Optional[int] = None,
        ecosystems: Optional[List[str]] = None,
    ) -> List[MaliciousPackage]:
        """
        Fetch malicious packages from OSV GCS bucket.

        Args:
            max_packages: Maximum number of packages to fetch (None for all)
            hours: Fetch packages modified within the last N hours (None for all time)
            ecosystems: List of ecosystems to fetch (None for all available ecosystems)

        Returns:
            List of MaliciousPackage entities

        Raises:
            FeedError: If the feed cannot be accessed or parsed
        """
        logger.info("Fetching malicious packages from OSV GCS bucket")

        # Reset cache stats for this fetch
        self._total_cache_hits = 0
        self._total_cache_misses = 0

        try:
            # If no ecosystems specified, get all available ecosystems with malicious packages
            if ecosystems is None:
                ecosystems = await self.get_available_ecosystems()
                logger.info(
                    f"No ecosystems specified, fetching from all available: {ecosystems}"
                )
            else:
                logger.info(f"Fetching from specified ecosystems: {ecosystems}")

            all_packages = []
            remaining_limit = max_packages

            # Process each ecosystem
            for ecosystem in ecosystems:
                try:
                    logger.info(f"Processing ecosystem: {ecosystem}")

                    # If we have a global limit, calculate how many we can still fetch
                    ecosystem_limit = (
                        remaining_limit if remaining_limit is not None else None
                    )

                    ecosystem_packages = (
                        await self._fetch_malicious_packages_for_ecosystem(
                            ecosystem, ecosystem_limit, hours
                        )
                    )
                    all_packages.extend(ecosystem_packages)
                    logger.info(
                        f"Fetched {len(ecosystem_packages)} packages from {ecosystem}"
                    )

                    # Update remaining limit
                    if remaining_limit is not None:
                        remaining_limit -= len(ecosystem_packages)
                        if remaining_limit <= 0:
                            logger.info(
                                f"Reached max_packages limit of {max_packages}, stopping"
                            )
                            break

                except Exception as e:
                    logger.warning(
                        f"Failed to fetch packages from ecosystem {ecosystem}: {e}"
                    )
                    continue

            logger.info(
                f"Successfully fetched {len(all_packages)} malicious packages from {len(ecosystems)} ecosystems"
            )
            return all_packages

        except Exception as e:
            logger.error(f"Failed to fetch malicious packages: {e}")
            raise FeedError(f"Failed to fetch OSV data: {e}") from e

    async def get_available_ecosystems(self) -> List[str]:
        """
        Get list of available ecosystems with malicious packages in OSV.

        Returns:
            List of ecosystem names that contain malicious packages (MAL- prefixed vulnerabilities)

        Raises:
            FeedError: If the ecosystems cannot be discovered
        """
        logger.info("Discovering available ecosystems with malicious packages")

        try:
            # Define known ecosystems that contain malicious packages based on OSV structure
            # These are the main package manager ecosystems that OSV tracks
            known_ecosystems = [
                "npm",
                "PyPI",
                "Maven",
                "Go",
                "NuGet",
                "crates.io",
                "RubyGems",
                "Packagist",
                "Pub",
                "Hex",
            ]

            available_ecosystems = []

            for ecosystem in known_ecosystems:
                try:
                    # Check if ecosystem has malicious packages by trying to read modified_id.csv
                    malicious_ids = await self._get_malicious_package_ids(
                        ecosystem, None
                    )
                    if malicious_ids:
                        available_ecosystems.append(ecosystem)
                        logger.debug(
                            f"Ecosystem {ecosystem} has {len(malicious_ids)} malicious packages"
                        )
                    else:
                        logger.debug(f"Ecosystem {ecosystem} has no malicious packages")
                except Exception as e:
                    logger.debug(
                        f"Ecosystem {ecosystem} not available or accessible: {e}"
                    )
                    continue

            logger.info(
                f"Found {len(available_ecosystems)} ecosystems with malicious packages: {available_ecosystems}"
            )
            return available_ecosystems

        except Exception as e:
            logger.error(f"Failed to discover available ecosystems: {e}")
            return []  # Return empty list on error for graceful degradation

    async def _fetch_malicious_packages_for_ecosystem(
        self,
        ecosystem: str,
        max_packages: Optional[int] = None,
        hours: Optional[int] = None,
    ) -> List[MaliciousPackage]:
        """Fetch malicious packages for a specific ecosystem from GCS bucket."""
        try:
            logger.info(f"Starting to fetch malicious packages for {ecosystem}")

            # Read the modified_id.csv file for the ecosystem
            malicious_ids = await self._get_malicious_package_ids(ecosystem, hours)

            logger.info(
                f"Found {len(malicious_ids)} malicious package IDs for {ecosystem}"
            )

            # Determine how many packages to fetch
            if max_packages is None:
                packages_to_fetch = len(malicious_ids)
                logger.info(f"Will fetch all {packages_to_fetch} packages")
            else:
                packages_to_fetch = min(len(malicious_ids), max_packages)
                logger.info(
                    f"Will fetch first {packages_to_fetch} packages (limited by max_packages={max_packages})"
                )

            # Parallel fetch with concurrency limit
            packages, cache_hits, cache_misses = await self._fetch_packages_parallel(
                ecosystem, malicious_ids[:packages_to_fetch]
            )

            # Store cache stats for this ecosystem
            if not hasattr(self, "_total_cache_hits"):
                self._total_cache_hits = 0
                self._total_cache_misses = 0
            self._total_cache_hits += cache_hits
            self._total_cache_misses += cache_misses

            logger.info(
                f"Successfully fetched {len(packages)} packages for {ecosystem}"
            )
            return packages

        except Exception as e:
            logger.error(f"Failed to fetch packages for ecosystem {ecosystem}: {e}")
            raise

    async def _fetch_packages_parallel(
        self, ecosystem: str, vuln_ids: List[str], max_concurrent: int = 10
    ) -> tuple[List[MaliciousPackage], int, int]:
        """
        Fetch multiple packages in parallel with concurrency control.

        Args:
            ecosystem: Package ecosystem
            vuln_ids: List of vulnerability IDs to fetch
            max_concurrent: Maximum concurrent requests (default: 10)

        Returns:
            Tuple of (list of MaliciousPackage objects, cache_hits, cache_misses)
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        packages = []
        total = len(vuln_ids)

        # Count cache hits
        cache_hits = sum(1 for vid in vuln_ids if self._cache.has(vid))
        cache_misses = total - cache_hits

        if total > 0:
            logger.info(
                f"Cache stats: {cache_hits} hits, {cache_misses} misses ({cache_hits/total*100:.1f}% hit rate)"
            )

        async def fetch_with_semaphore(
            idx: int, vuln_id: str
        ) -> Optional[MaliciousPackage]:
            """Fetch a single package with semaphore control."""
            async with semaphore:
                try:
                    if (idx + 1) % 50 == 0:
                        logger.info(f"Progress: {idx + 1}/{total} packages fetched")
                    package = await self._fetch_malicious_package(ecosystem, vuln_id)
                    if package:
                        return package
                    else:
                        logger.warning(f"Failed to parse package {vuln_id}")
                        return None
                except Exception as e:
                    logger.warning(f"Failed to fetch package {vuln_id}: {e}")
                    return None

        # Fetch all packages in parallel
        logger.info(
            f"Fetching {total} packages with max {max_concurrent} concurrent requests"
        )
        results = await asyncio.gather(
            *[fetch_with_semaphore(i, vuln_id) for i, vuln_id in enumerate(vuln_ids)],
            return_exceptions=False,
        )

        # Filter out None results
        packages = [pkg for pkg in results if pkg is not None]
        logger.info(f"Successfully fetched {len(packages)}/{total} packages")
        return packages, cache_hits, cache_misses

    async def _get_malicious_package_ids(
        self, ecosystem: str, hours: Optional[int] = None
    ) -> List[str]:
        """Get list of malicious package IDs from modified_id.csv."""
        csv_path = f"{ecosystem}/modified_id.csv"

        # Calculate cutoff time if hours is specified
        cutoff_time = None
        if hours is not None:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            logger.info(
                f"Filtering packages modified after: {cutoff_time.isoformat()}Z (last {hours} hours)"
            )

        for attempt in range(self.max_retries + 1):
            try:
                logger.info(f"Attempting to read {csv_path} from GCS bucket")

                # Run the synchronous GCS operations in an executor
                def read_csv():
                    bucket = self._get_bucket()
                    blob = bucket.blob(csv_path)
                    return blob.download_as_text()

                # Execute in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                csv_content = await loop.run_in_executor(None, read_csv)

                logger.info(
                    f"Successfully downloaded CSV, size: {len(csv_content)} bytes"
                )

                # Parse CSV and filter for malicious packages (MAL prefix)
                malicious_ids = []
                csv_reader = csv.reader(io.StringIO(csv_content))

                for row in csv_reader:
                    if len(row) >= 2:
                        # Format: timestamp,vulnerability_id
                        timestamp_str = row[0].strip()
                        vuln_id = row[1].strip()

                        # Filter by MAL prefix
                        if not vuln_id.startswith("MAL-"):
                            continue

                        # Filter by time if specified
                        if cutoff_time is not None:
                            try:
                                # Parse timestamp (format: 2025-09-17T07:30:43Z)
                                package_time = datetime.fromisoformat(
                                    timestamp_str.replace("Z", "+00:00")
                                )
                                # Convert to UTC for comparison
                                package_time_utc = package_time.replace(tzinfo=None)

                                if package_time_utc < cutoff_time:
                                    continue
                            except ValueError as e:
                                logger.warning(
                                    f"Failed to parse timestamp '{timestamp_str}': {e}"
                                )
                                continue

                        malicious_ids.append(vuln_id)

                logger.info(
                    f"Found {len(malicious_ids)} malicious packages in {ecosystem}"
                )
                if cutoff_time:
                    logger.info(f"  (filtered to last {hours} hours)")
                return malicious_ids

            except gcs_exceptions.NotFound:
                raise FeedError(f"Modified ID file not found for ecosystem {ecosystem}")
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                    continue
                raise FeedError(
                    f"Failed to read modified_id.csv for {ecosystem}: {e}"
                ) from e

        return []

    async def _fetch_malicious_package(
        self, ecosystem: str, vuln_id: str
    ) -> Optional[MaliciousPackage]:
        """Fetch a single malicious package JSON from GCS bucket."""
        # Check cache first
        cached_package = self._cache.get(vuln_id)
        if cached_package is not None:
            logger.info(f"Cache hit for {vuln_id}")
            return cached_package

        logger.info(f"Cache miss for {vuln_id}, fetching from GCS")
        json_path = f"{ecosystem}/{vuln_id}.json"

        for attempt in range(self.max_retries + 1):
            try:
                # Download the JSON file using executor
                def download_json():
                    bucket = self._get_bucket()
                    blob = bucket.blob(json_path)
                    if not blob.exists():
                        return None
                    return blob.download_as_text()

                # Execute in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                json_content = await loop.run_in_executor(None, download_json)

                if json_content is None:
                    logger.warning(f"JSON file not found for {vuln_id}")
                    return None

                # Parse JSON
                vuln_data = json.loads(json_content)

                # Convert to MaliciousPackage entity
                package = self._parse_malicious_package(vuln_data)

                # Store in cache
                if package:
                    self._cache.put(vuln_id, package)

                return package

            except Exception as e:
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                    continue
                logger.error(f"Failed to fetch package {vuln_id}: {e}")
                return None

        return None

    def _parse_malicious_package(
        self, vuln_data: Dict[str, Any]
    ) -> Optional[MaliciousPackage]:
        """Parse malicious package data from OSV JSON into MaliciousPackage entity."""
        try:
            # Extract package information from affected array
            affected = vuln_data.get("affected", [])
            if not affected:
                logger.warning(
                    f"No affected packages found in vulnerability {vuln_data.get('id', 'unknown')}"
                )
                return None

            # Get the first affected package (malicious packages typically affect one package)
            package_info = affected[0].get("package", {})
            package_name = package_info.get("name")
            ecosystem = package_info.get("ecosystem")

            if not package_name or not ecosystem:
                logger.warning(
                    f"Missing package name or ecosystem in vulnerability {vuln_data.get('id', 'unknown')}"
                )
                return None

            # Extract affected versions
            affected_versions = affected[0].get("versions", [])

            # Parse dates
            published_at = self._parse_date(vuln_data.get("published"))
            modified_at = self._parse_date(vuln_data.get("modified"))

            # Extract summary and details
            summary = vuln_data.get("summary", "")
            details = vuln_data.get("details", "")

            # Get database specific information
            database_specific = vuln_data.get("database_specific", {})
            malicious_origins = database_specific.get("malicious-packages-origins", [])

            # Extract additional metadata from malicious package origins
            if malicious_origins:
                origin = malicious_origins[0]
                if not details and "source" in origin:
                    details = f"Malicious package detected. Source: {origin.get('source', 'Unknown')}"

            return MaliciousPackage(
                name=package_name,
                version=affected_versions[0] if affected_versions else None,
                ecosystem=ecosystem,
                package_url=package_info.get("purl"),
                advisory_id=vuln_data.get("id"),
                summary=summary,
                details=details,
                aliases=vuln_data.get("aliases", []),
                affected_versions=affected_versions,
                database_specific=database_specific,
                published_at=published_at,
                modified_at=modified_at,
            )

        except Exception as e:
            logger.warning(f"Failed to parse malicious package data: {e}")
            return None

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime."""
        if not date_str:
            return None

        try:
            # Handle different date formats
            if date_str.endswith("Z"):
                return datetime.fromisoformat(date_str[:-1] + "+00:00")
            else:
                return datetime.fromisoformat(date_str)
        except ValueError:
            return None

    async def health_check(self) -> bool:
        """Check if OSV GCS bucket is accessible."""
        try:
            bucket = self._get_bucket()
            # Try to check if bucket exists and is accessible
            bucket.reload()
            return True
        except Exception:
            return False

    async def close(self):
        """Close resources - no persistent connections to close for GCS client."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
