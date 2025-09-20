"""Registry Management Use Case for package registry operations."""

import logging
from typing import Optional, Dict, List, Any

from ..interfaces.packages_registry_service import PackagesRegistryService


class RegistryManagementUseCase:
    """Use case for registry management operations."""
    
    def __init__(self, registry_service: PackagesRegistryService):
        """
        Initialize the registry management use case.
        
        Args:
            registry_service: Service for interacting with package registry
        """
        self.registry_service = registry_service
        self.logger = logging.getLogger(__name__)
    
    async def search_package(self, package_name: str, ecosystem: str = "npm") -> Dict[str, Any]:
        """
        Search for a package in the registry.
        
        Args:
            package_name: Name of the package to search
            ecosystem: Package ecosystem (default: npm)
            
        Returns:
            Dictionary containing search results and metadata
        """
        try:
            self.logger.debug(f"Searching for package: {package_name} ({ecosystem})")
            
            # Check registry health first
            registry_healthy = await self.registry_service.health_check()
            
            if not registry_healthy:
                return {
                    "success": False,
                    "error": "Registry is not accessible",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "registry_healthy": False,
                    "search_results": [],
                    "results_count": 0,
                    "is_blocked": False
                }
            
            # Search for the package
            search_results = await self.registry_service.search_packages(package_name, ecosystem)
            
            # Check if package is currently blocked (create a minimal package object for checking)
            from ..entities.malicious_package import MaliciousPackage
            temp_package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version="*",
                package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                advisory_id="TEMP-CHECK",
                summary="Temporary package for blocking check",
                details="",
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=None,
                modified_at=None
            )
            is_blocked = await self.registry_service.is_package_blocked(temp_package)
            
            return {
                "success": True,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "registry_healthy": registry_healthy,
                "search_results": search_results or [],
                "results_count": len(search_results) if search_results else 0,
                "is_blocked": is_blocked
            }
            
        except Exception as e:
            self.logger.error(f"Error searching for package {package_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "package_name": package_name,
                "ecosystem": ecosystem,
                "registry_healthy": False,
                "search_results": [],
                "results_count": 0,
                "is_blocked": False
            }
        finally:
            # Ensure session is properly closed
            await self.registry_service.close()
    
    async def block_package(self, package_name: str, ecosystem: str = "npm", version: str = "*") -> Dict[str, Any]:
        """
        Block a package in the registry.
        
        Args:
            package_name: Name of the package to block
            ecosystem: Package ecosystem (default: npm)
            version: Package version (* for all versions)
            
        Returns:
            Dictionary containing operation results
        """
        try:
            self.logger.debug(f"Blocking package: {package_name} ({ecosystem}) version {version}")
            
            # Check registry health first
            registry_healthy = await self.registry_service.health_check()
            
            if not registry_healthy:
                return {
                    "success": False,
                    "error": "Registry is not accessible",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": False
                }
            
            # Check if already blocked
            from ..entities.malicious_package import MaliciousPackage
            temp_package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version=version,
                package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                advisory_id="TEMP-BLOCK",
                summary="Temporary package for blocking",
                details="",
                aliases=[],
                affected_versions=[version] if version != "*" else [],
                database_specific={},
                published_at=None,
                modified_at=None
            )
            is_already_blocked = await self.registry_service.is_package_blocked(temp_package)
            
            if is_already_blocked:
                return {
                    "success": True,
                    "message": f"Package {package_name} ({ecosystem}) version {version} is already blocked",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy,
                    "already_blocked": True
                }
            
            # Block the package
            block_result = await self.registry_service.block_packages([temp_package])
            
            if block_result:
                return {
                    "success": True,
                    "message": f"Successfully blocked package {package_name} ({ecosystem}) version {version}",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy,
                    "already_blocked": False
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to block package",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy
                }
                
        except Exception as e:
            self.logger.error(f"Error blocking package {package_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "registry_healthy": False
            }
        finally:
            # Ensure session is properly closed
            await self.registry_service.close()
    
    async def unblock_package(self, package_name: str, ecosystem: str = "npm", version: str = "*") -> Dict[str, Any]:
        """
        Unblock a package in the registry.
        
        Args:
            package_name: Name of the package to unblock
            ecosystem: Package ecosystem (default: npm)
            version: Package version (* for all versions)
            
        Returns:
            Dictionary containing operation results
        """
        try:
            self.logger.debug(f"Unblocking package: {package_name} ({ecosystem}) version {version}")
            
            # Check registry health first
            registry_healthy = await self.registry_service.health_check()
            
            if not registry_healthy:
                return {
                    "success": False,
                    "error": "Registry is not accessible",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": False
                }
            
            # Check if currently blocked
            from ..entities.malicious_package import MaliciousPackage
            temp_package = MaliciousPackage(
                name=package_name,
                ecosystem=ecosystem,
                version=version,
                package_url=f"pkg:{ecosystem.lower()}/{package_name}",
                advisory_id="TEMP-UNBLOCK",
                summary="Temporary package for unblocking",
                details="",
                aliases=[],
                affected_versions=[version] if version != "*" else [],
                database_specific={},
                published_at=None,
                modified_at=None
            )
            is_blocked = await self.registry_service.is_package_blocked(temp_package)
            
            if not is_blocked:
                return {
                    "success": True,
                    "message": f"Package {package_name} ({ecosystem}) version {version} is not currently blocked",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy,
                    "was_blocked": False
                }
            
            # Unblock the package
            unblock_result = await self.registry_service.unblock_packages([temp_package])
            
            if unblock_result:
                return {
                    "success": True,
                    "message": f"Successfully unblocked package {package_name} ({ecosystem}) version {version}",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy,
                    "was_blocked": True
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to unblock package",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "registry_healthy": registry_healthy
                }
                
        except Exception as e:
            self.logger.error(f"Error unblocking package {package_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "registry_healthy": False
            }
        finally:
            # Ensure session is properly closed
            await self.registry_service.close()
    
    async def list_blocked_packages(self, ecosystem: str = "npm") -> Dict[str, Any]:
        """
        List currently blocked packages by ecosystem.
        
        Args:
            ecosystem: Package ecosystem (default: npm)
            
        Returns:
            Dictionary containing blocked packages information
        """
        try:
            self.logger.debug(f"Listing blocked packages for ecosystem: {ecosystem}")
            
            # Check registry health first
            registry_healthy = await self.registry_service.health_check()
            
            if not registry_healthy:
                return {
                    "success": False,
                    "error": "Registry is not accessible",
                    "ecosystem": ecosystem,
                    "registry_healthy": False,
                    "blocked_packages": []
                }
            
            # Get blocked packages
            blocked_packages = await self.registry_service.list_blocked_packages(ecosystem)
            
            return {
                "success": True,
                "ecosystem": ecosystem,
                "registry_healthy": registry_healthy,
                "blocked_packages": blocked_packages or [],
                "count": len(blocked_packages) if blocked_packages else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error listing blocked packages for {ecosystem}: {e}")
            return {
                "success": False,
                "error": str(e),
                "ecosystem": ecosystem,
                "registry_healthy": False,
                "blocked_packages": []
            }
        finally:
            # Ensure session is properly closed
            await self.registry_service.close()
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check registry health.
        
        Returns:
            Dictionary containing health status
        """
        try:
            self.logger.debug("Checking registry health")
            
            is_healthy = await self.registry_service.health_check()
            registry_name = self.registry_service.get_registry_name()
            
            return {
                "success": True,
                "healthy": is_healthy,
                "registry_name": registry_name
            }
            
        except Exception as e:
            self.logger.error(f"Error checking registry health: {e}")
            return {
                "success": False,
                "error": str(e),
                "healthy": False,
                "registry_name": "Unknown"
            }
        finally:
            # Ensure session is properly closed
            await self.registry_service.close()