"""Test Data Management Use Case for creating test malicious packages."""

from typing import Dict, Any
import logging
from datetime import datetime

from src.core.entities.malicious_package import MaliciousPackage
from src.core.interfaces.storage_service import StorageService


class TestDataManagementUseCase:
    """Use case for test data management operations."""
    
    def __init__(self, storage_service: StorageService):
        """
        Initialize the test data management use case.
        
        Args:
            storage_service: Service for storing test data
        """
        self.storage_service = storage_service
        self.logger = logging.getLogger(__name__)
    
    async def create_test_malicious_packages(self) -> Dict[str, Any]:
        """
        Create test malicious packages for testing purposes.
        
        Returns:
            Dictionary containing creation results
        """
        try:
            self.logger.info("Creating test malicious packages")
            
            # Create test malicious packages
            test_packages = [
                MaliciousPackage(
                    name="evil-test-package",
                    ecosystem="npm",
                    version="1.0.0",
                    package_url="pkg:npm/evil-test-package@1.0.0",
                    advisory_id="CLI-TEST-001",
                    summary="Test malicious package created by CLI",
                    details="This is a test package for CLI testing purposes",
                    aliases=["TEST-CVE-001"],
                    affected_versions=["1.0.0"],
                    database_specific={},
                    published_at=datetime.now(),
                    modified_at=datetime.now()
                ),
                MaliciousPackage(
                    name="malware-simulator",
                    ecosystem="PyPI",
                    version="2.1.0",
                    package_url="pkg:pypi/malware-simulator@2.1.0",
                    advisory_id="CLI-TEST-002",
                    summary="Python malware simulator for testing",
                    details="Simulates malware behavior for security testing",
                    aliases=["TEST-CVE-002"],
                    affected_versions=["2.0.0", "2.1.0"],
                    database_specific={},
                    published_at=datetime.now(),
                    modified_at=datetime.now()
                )
            ]
            
            # Store test packages
            success = await self.storage_service.store_malicious_packages(test_packages)
            
            if success:
                self.logger.info(f"Created {len(test_packages)} test packages")
                return {
                    "success": True,
                    "packages_created": test_packages,
                    "count": len(test_packages)
                }
            else:
                self.logger.warning("Failed to create test packages")
                return {
                    "success": False,
                    "error": "Failed to store test packages",
                    "packages_created": [],
                    "count": 0
                }
            
        except Exception as e:
            self.logger.error(f"Error creating test packages: {e}")
            return {
                "success": False,
                "error": str(e),
                "packages_created": [],
                "count": 0
            }