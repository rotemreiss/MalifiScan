"""File-based storage provider."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from src.core.entities import MaliciousPackage, ScanResult, ScanStatus
from src.core.interfaces import PackagesRegistryService, StorageService
from src.providers.exceptions import StorageError

logger = logging.getLogger(__name__)


class FileStorage(StorageService):
    """File-based storage provider using individual JSON files per scan."""

    def __init__(self, data_directory: str = "scan_results"):
        """
        Initialize file storage provider.

        Args:
            data_directory: Directory to store scan result files
        """
        self.data_directory = Path(data_directory)

        # Ensure data directory exists
        self.data_directory.mkdir(parents=True, exist_ok=True)

        logger.debug(f"File storage initialized with directory: {self.data_directory}")

    async def store_scan_result(
        self,
        scan_result: ScanResult,
        registry_service: PackagesRegistryService = None,
    ) -> bool:
        """
        Store a scan result as an individual JSON file.

        Args:
            scan_result: The scan result to store

        Returns:
            True if stored successfully, False otherwise
        """
        logger.debug(f"Storing scan result: {scan_result.scan_id}")

        try:
            # Create filename based on scan ID
            filename = f"{scan_result.scan_id}.json"
            file_path = self.data_directory / filename

            # Convert scan result to JSON
            result_data = self._scan_result_to_dict(scan_result)

            # Write to file
            async with aiofiles.open(file_path, mode="w", encoding="utf-8") as f:
                await f.write(json.dumps(result_data, indent=2, default=str))

            logger.debug(
                f"Successfully stored scan result: {scan_result.scan_id} to {file_path}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to store scan result: {e}")
            raise StorageError(f"Failed to store scan result: {e}") from e

    async def get_scan_results(
        self, limit: Optional[int] = None, scan_id: Optional[str] = None
    ) -> List[ScanResult]:
        """
        Retrieve scan results from files.

        Args:
            limit: Maximum number of results to return
            scan_id: Specific scan ID to retrieve

        Returns:
            List of scan results
        """
        logger.debug(f"Retrieving scan results (limit={limit}, scan_id={scan_id})")

        try:
            scan_results = []

            if scan_id:
                # Get specific scan result
                file_path = self.data_directory / f"{scan_id}.json"
                if file_path.exists():
                    async with aiofiles.open(
                        file_path, mode="r", encoding="utf-8"
                    ) as f:
                        content = await f.read()
                        result_data = json.loads(content)
                        scan_result = self._dict_to_scan_result(result_data)
                        scan_results.append(scan_result)
            else:
                # Get all scan results
                json_files = list(self.data_directory.glob("*.json"))

                # Sort by modification time (newest first)
                json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

                # Apply limit
                if limit:
                    json_files = json_files[:limit]

                for file_path in json_files:
                    try:
                        async with aiofiles.open(
                            file_path, mode="r", encoding="utf-8"
                        ) as f:
                            content = await f.read()
                            result_data = json.loads(content)
                            scan_result = self._dict_to_scan_result(result_data)
                            scan_results.append(scan_result)
                    except Exception as e:
                        logger.warning(
                            f"Failed to parse scan result file {file_path}: {e}"
                        )
                        continue

            logger.debug(f"Retrieved {len(scan_results)} scan results")
            return scan_results

        except Exception as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            raise StorageError(f"Failed to retrieve scan results: {e}") from e

    async def get_known_malicious_packages(self) -> List[MaliciousPackage]:
        """
        Get list of previously identified malicious packages from all scan results.

        Returns:
            List of known malicious packages
        """
        logger.debug("Retrieving known malicious packages from scan results")

        try:
            # Get all scan results and extract malicious packages
            all_scan_results = await self.get_scan_results()

            # Use a dictionary to avoid duplicates based on package_identifier
            unique_packages = {}

            for scan_result in all_scan_results:
                for package in scan_result.malicious_packages_found:
                    unique_packages[package.package_identifier] = package

                for package in scan_result.malicious_packages_list:
                    unique_packages[package.package_identifier] = package

            packages = list(unique_packages.values())
            logger.debug(f"Retrieved {len(packages)} known malicious packages")
            return packages

        except Exception as e:
            logger.error(f"Failed to retrieve known malicious packages: {e}")
            raise StorageError(
                f"Failed to retrieve known malicious packages: {e}"
            ) from e

    async def store_malicious_packages(self, packages: List[MaliciousPackage]) -> bool:
        """
        Store malicious packages (not implemented for file storage).

        Malicious packages are automatically stored as part of scan results.
        This method exists for interface compatibility.

        Args:
            packages: List of malicious packages to store

        Returns:
            True (packages are stored in scan results)
        """
        logger.debug(
            f"Malicious packages are stored as part of scan results, nothing to do for {len(packages)} packages"
        )
        return True

    async def get_scan_summary(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get scan summaries with basic metadata.

        This method is not supported by file storage - scan results feature
        is only available with database storage.

        Args:
            limit: Maximum number of scan summaries to return

        Raises:
            NotImplementedError: File storage doesn't support scan summaries
        """
        raise NotImplementedError(
            "Scan results functionality is only supported by database storage. "
            "Please configure the application to use DatabaseStorage to access scan summaries."
        )

    async def health_check(self) -> bool:
        """
        Check if storage directory is accessible and writable.

        Returns:
            True if service is healthy, False otherwise
        """
        try:
            # Test write access
            test_file = self.data_directory / ".health_check"

            async with aiofiles.open(test_file, mode="w") as f:
                await f.write("health_check")

            # Test read access
            async with aiofiles.open(test_file, mode="r") as f:
                content = await f.read()
                if content != "health_check":
                    return False

            # Clean up
            test_file.unlink()

            return True

        except Exception:
            return False

    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dictionary."""
        return {
            "scan_id": scan_result.scan_id,
            "timestamp": scan_result.timestamp.isoformat(),
            "status": scan_result.status.value,
            "packages_scanned": scan_result.packages_scanned,
            "malicious_packages_found": [
                self._malicious_package_to_dict(pkg)
                for pkg in scan_result.malicious_packages_found
            ],
            "packages_blocked": scan_result.packages_blocked,
            "malicious_packages_list": [
                self._simplified_malicious_package_to_dict(pkg)
                for pkg in scan_result.malicious_packages_list
            ],
            "errors": scan_result.errors,
            "execution_duration_seconds": scan_result.execution_duration_seconds,
        }

    def _dict_to_scan_result(self, data: Dict[str, Any]) -> ScanResult:
        """Convert dictionary to ScanResult."""
        # Handle backwards compatibility for old scan results that use packages_already_present
        malicious_list_key = (
            "malicious_packages_list"
            if "malicious_packages_list" in data
            else "packages_already_present"
        )

        return ScanResult(
            scan_id=data["scan_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            status=ScanStatus(data["status"]),
            packages_scanned=data["packages_scanned"],
            malicious_packages_found=[
                self._dict_to_malicious_package(pkg_data)
                for pkg_data in data["malicious_packages_found"]
            ],
            packages_blocked=data["packages_blocked"],
            malicious_packages_list=[
                self._dict_to_malicious_package(pkg_data)
                for pkg_data in data[malicious_list_key]
            ],
            errors=data["errors"],
            execution_duration_seconds=data["execution_duration_seconds"],
        )

    def _malicious_package_to_dict(self, package: MaliciousPackage) -> Dict[str, Any]:
        """Convert MaliciousPackage to dictionary."""
        return {
            "name": package.name,
            "version": package.version,
            "ecosystem": package.ecosystem,
            "package_url": package.package_url,
            "advisory_id": package.advisory_id,
            "summary": package.summary,
            "details": package.details,
            "aliases": package.aliases,
            "affected_versions": package.affected_versions,
            "database_specific": package.database_specific,
            "published_at": (
                package.published_at.isoformat() if package.published_at else None
            ),
            "modified_at": (
                package.modified_at.isoformat() if package.modified_at else None
            ),
        }

    def _simplified_malicious_package_to_dict(
        self, package: MaliciousPackage
    ) -> Dict[str, Any]:
        """Convert MaliciousPackage to simplified dictionary with only essential fields."""
        return {
            "name": package.name,
            "ecosystem": package.ecosystem,
            "advisory_id": package.advisory_id,
            "affected_versions": package.affected_versions,
        }

    def _dict_to_malicious_package(self, data: Dict[str, Any]) -> MaliciousPackage:
        """Convert dictionary to MaliciousPackage."""
        return MaliciousPackage(
            name=data["name"],
            version=data.get("version"),
            ecosystem=data["ecosystem"],
            package_url=data.get("package_url"),
            advisory_id=data.get("advisory_id"),
            summary=data.get("summary"),
            details=data.get("details"),
            aliases=data.get("aliases", []),
            affected_versions=data.get("affected_versions", []),
            database_specific=data.get("database_specific", {}),
            published_at=(
                datetime.fromisoformat(data["published_at"])
                if data.get("published_at")
                else None
            ),
            modified_at=(
                datetime.fromisoformat(data["modified_at"])
                if data.get("modified_at")
                else None
            ),
        )
