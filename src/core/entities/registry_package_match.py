"""
Registry package data structures for dynamic field naming.

This module provides data classes for handling package version information
with dynamic field naming based on registry type, avoiding hardcoded
registry-specific field names.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from .malicious_package import MaliciousPackage


@dataclass
class RegistryPackageMatch:
    """
    Represents a package match with dynamic field naming based on registry type.
    
    This class encapsulates package match information and provides methods
    to generate dictionaries with appropriate field names based on the
    registry being used.
    """
    package: MaliciousPackage
    registry_name: str
    registry_results: Optional[List[Dict[str, Any]]] = None
    matching_versions: Optional[List[str]] = None
    all_registry_versions: Optional[List[str]] = None
    malicious_versions: Optional[List[str]] = None
    
    def to_match_dict(self) -> Dict[str, Any]:
        """
        Convert to a dictionary format for critical matches.
        
        Returns:
            Dictionary with dynamic field names based on registry
        """
        registry_lower = self.registry_name.lower()
        
        return {
            'package': self.package,
            f'{registry_lower}_results': self.registry_results or [],
            'matching_versions': self.matching_versions or [],
            f'all_{registry_lower}_versions': self.all_registry_versions or [],
            'malicious_versions': self.malicious_versions or []
        }
    
    def to_safe_dict(self) -> Dict[str, Any]:
        """
        Convert to a dictionary format for safe packages.
        
        Returns:
            Dictionary with dynamic field names based on registry
        """
        registry_lower = self.registry_name.lower()
        
        return {
            'package': self.package,
            f'{registry_lower}_results': self.registry_results or [],
            f'{registry_lower}_versions': self.all_registry_versions or [],
            'malicious_versions': self.malicious_versions or []
        }
    
    def get_all_versions_field_name(self) -> str:
        """Get the field name for all registry versions."""
        return f'all_{self.registry_name.lower()}_versions'
    
    def get_versions_field_name(self) -> str:
        """Get the field name for registry versions."""
        return f'{self.registry_name.lower()}_versions'
    
    def get_results_field_name(self) -> str:
        """Get the field name for registry results."""
        return f'{self.registry_name.lower()}_results'


class RegistryPackageMatchBuilder:
    """
    Builder class for creating RegistryPackageMatch instances.
    
    This class provides a convenient way to build RegistryPackageMatch
    instances with the appropriate registry context.
    """
    
    def __init__(self, registry_name: str):
        """
        Initialize the builder with a registry name.
        
        Args:
            registry_name: Name of the registry (e.g., "JFrog", "NPM", etc.)
        """
        self.registry_name = registry_name
    
    def build_match(
        self,
        package: MaliciousPackage,
        registry_results: Optional[List[Dict[str, Any]]] = None,
        matching_versions: Optional[List[str]] = None,
        all_registry_versions: Optional[List[str]] = None,
        malicious_versions: Optional[List[str]] = None
    ) -> RegistryPackageMatch:
        """
        Build a RegistryPackageMatch instance.
        
        Args:
            package: The malicious package
            registry_results: Results from the registry
            matching_versions: Versions that match between registry and malicious
            all_registry_versions: All versions found in registry
            malicious_versions: All malicious versions
            
        Returns:
            RegistryPackageMatch instance
        """
        return RegistryPackageMatch(
            package=package,
            registry_name=self.registry_name,
            registry_results=registry_results,
            matching_versions=matching_versions,
            all_registry_versions=all_registry_versions,
            malicious_versions=malicious_versions
        )
    
    def build_from_finding(
        self,
        finding: MaliciousPackage,
        registry_results: Optional[List[Dict[str, Any]]] = None
    ) -> RegistryPackageMatch:
        """
        Build a RegistryPackageMatch from a scan finding.
        
        Args:
            finding: The package finding from scan results
            registry_results: Optional registry search results
            
        Returns:
            RegistryPackageMatch instance
        """
        all_versions = [finding.version] if finding.version else []
        malicious_versions = finding.affected_versions or ([finding.version] if finding.version else [])
        matching_versions = [finding.version] if finding.version and finding.version in malicious_versions else []
        
        return self.build_match(
            package=finding,
            registry_results=registry_results,
            matching_versions=matching_versions,
            all_registry_versions=all_versions,
            malicious_versions=malicious_versions
        )