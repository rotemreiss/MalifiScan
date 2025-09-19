"""Scan result entity."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

from .malicious_package import MaliciousPackage


class ScanStatus(Enum):
    """Status of a package scan."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass(frozen=True)
class ScanResult:
    """Represents the result of a malicious packages scan."""
    
    scan_id: str
    timestamp: datetime
    status: ScanStatus
    packages_scanned: int
    malicious_packages_found: List[MaliciousPackage]
    packages_blocked: List[str]
    malicious_packages_list: List[MaliciousPackage]  # Previously packages_already_present
    errors: List[str]
    execution_duration_seconds: float
    
    @property
    def has_new_threats(self) -> bool:
        """Check if new threats were found in this scan."""
        return len(self.malicious_packages_found) > len(self.malicious_packages_list)
    
    @property
    def new_threats_count(self) -> int:
        """Count of new threats discovered."""
        return len(self.malicious_packages_found) - len(self.malicious_packages_list)
    
    @property
    def is_successful(self) -> bool:
        """Check if the scan completed successfully."""
        return self.status == ScanStatus.SUCCESS