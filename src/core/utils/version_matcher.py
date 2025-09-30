"""
Unified version matching utilities for security analysis.

This module provides consistent version matching logic that can be used
across different parts of the application (crossref, scan results, etc.)
to ensure consistent categorization of packages as critical vs safe.
"""

from typing import List

from src.core.entities.malicious_package import MaliciousPackage


class VersionMatcher:
    """Utility class for consistent version matching across the application."""

    @staticmethod
    def is_critical_match(
        registry_versions: List[str], malicious_versions: List[str]
    ) -> bool:
        """
        Determine if a package has critical vulnerabilities based on version overlap.

        Args:
            registry_versions: List of versions found in the registry
            malicious_versions: List of versions that are known to be malicious

        Returns:
            True if there are overlapping versions (critical match), False otherwise
        """
        if not registry_versions or not malicious_versions:
            return False

        # Convert to sets for efficient intersection
        registry_set = set(registry_versions)
        malicious_set = set(malicious_versions)

        # Check for any overlap
        return bool(registry_set & malicious_set)

    @staticmethod
    def get_matching_versions(
        registry_versions: List[str], malicious_versions: List[str]
    ) -> List[str]:
        """
        Get the specific versions that match between registry and malicious versions.

        Args:
            registry_versions: List of versions found in the registry
            malicious_versions: List of versions that are known to be malicious

        Returns:
            List of versions that exist in both lists
        """
        if not registry_versions or not malicious_versions:
            return []

        # Convert to sets for efficient intersection
        registry_set = set(registry_versions)
        malicious_set = set(malicious_versions)

        # Return sorted list of matching versions
        return sorted(list(registry_set & malicious_set))

    @staticmethod
    def is_finding_critical(finding: MaliciousPackage) -> bool:
        """
        Determine if a stored finding represents a critical match.

        This method handles the specific case where we have a stored finding
        and need to determine if it represents a critical vulnerability.

        Args:
            finding: The malicious package finding

        Returns:
            True if this finding represents a critical match, False otherwise
        """
        if not finding.version:
            return False

        affected_versions = finding.affected_versions or []
        if not affected_versions:
            # If no affected versions specified but we have a version,
            # assume it's critical (backward compatibility)
            return True

        return finding.version in affected_versions
