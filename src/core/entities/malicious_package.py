"""Malicious package entity."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass(frozen=True)
class MaliciousPackage:
    """Represents a malicious package identified in the feed."""

    name: str
    version: Optional[str]
    ecosystem: str  # e.g., "PyPI", "npm", "Maven"
    package_url: Optional[str]
    advisory_id: Optional[str]
    summary: Optional[str]
    details: Optional[str]
    aliases: List[str]
    affected_versions: List[str]
    database_specific: dict
    published_at: Optional[datetime]
    modified_at: Optional[datetime]

    def __post_init__(self):
        """Validate package data."""
        if not self.name or not self.name.strip():
            raise ValueError("Package name cannot be empty")
        if not self.ecosystem or not self.ecosystem.strip():
            raise ValueError("Ecosystem cannot be empty")

    @property
    def package_identifier(self) -> str:
        """Get unique package identifier."""
        if self.version:
            return f"{self.ecosystem}:{self.name}:{self.version}"
        return f"{self.ecosystem}:{self.name}"

    def matches_package(self, name: str, version: Optional[str] = None) -> bool:
        """Check if this malicious package matches the given package."""
        if self.name.lower() != name.lower():
            return False

        if version is None:
            return True

        # If no specific version is tracked, consider it a match
        if not self.affected_versions:
            return True

        # Check if the version is in the affected versions list
        return version in self.affected_versions

    def to_dict(self) -> dict:
        """
        Convert package to dictionary for serialization.

        Returns:
            Dictionary representation of the package
        """
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "package_url": self.package_url,
            "advisory_id": self.advisory_id,
            "summary": self.summary,
            "details": self.details,
            "aliases": self.aliases,
            "affected_versions": self.affected_versions,
            "database_specific": self.database_specific,
            "published_at": (
                self.published_at.isoformat() if self.published_at else None
            ),
            "modified_at": self.modified_at.isoformat() if self.modified_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MaliciousPackage":
        """
        Create package from dictionary.

        Args:
            data: Dictionary with package data

        Returns:
            MaliciousPackage instance
        """
        # Parse datetime fields
        published_at = None
        if data.get("published_at"):
            published_at = datetime.fromisoformat(data["published_at"])

        modified_at = None
        if data.get("modified_at"):
            modified_at = datetime.fromisoformat(data["modified_at"])

        return cls(
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
            published_at=published_at,
            modified_at=modified_at,
        )
