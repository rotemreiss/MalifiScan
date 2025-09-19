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