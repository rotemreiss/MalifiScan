"""
Unit tests for VersionMatcher utility class.
"""
import pytest
from src.core.utils.version_matcher import VersionMatcher
from src.core.entities.malicious_package import MaliciousPackage


class TestVersionMatcher:
    """Test cases for VersionMatcher utility class."""
    
    def test_is_critical_match_with_overlap(self):
        """Test is_critical_match returns True when versions overlap."""
        registry_versions = ["1.0.0", "1.0.1", "2.0.0"]
        malicious_versions = ["1.0.1", "1.0.2"]
        
        assert VersionMatcher.is_critical_match(registry_versions, malicious_versions) is True
    
    def test_is_critical_match_no_overlap(self):
        """Test is_critical_match returns False when no versions overlap."""
        registry_versions = ["1.0.0", "1.0.1", "2.0.0"]
        malicious_versions = ["1.0.2", "1.0.3"]
        
        assert VersionMatcher.is_critical_match(registry_versions, malicious_versions) is False
    
    def test_is_critical_match_empty_lists(self):
        """Test is_critical_match handles empty lists correctly."""
        assert VersionMatcher.is_critical_match([], ["1.0.0"]) is False
        assert VersionMatcher.is_critical_match(["1.0.0"], []) is False
        assert VersionMatcher.is_critical_match([], []) is False
    
    def test_get_matching_versions(self):
        """Test get_matching_versions returns correct overlapping versions."""
        registry_versions = ["1.0.0", "1.0.1", "2.0.0"]
        malicious_versions = ["1.0.1", "2.0.0", "1.0.2"]
        
        expected = ["1.0.1", "2.0.0"]
        actual = VersionMatcher.get_matching_versions(registry_versions, malicious_versions)
        
        assert sorted(actual) == sorted(expected)
    
    def test_get_matching_versions_no_overlap(self):
        """Test get_matching_versions returns empty list when no overlap."""
        registry_versions = ["1.0.0", "1.0.1"]
        malicious_versions = ["1.0.2", "1.0.3"]
        
        assert VersionMatcher.get_matching_versions(registry_versions, malicious_versions) == []
    
    def test_is_finding_critical_with_version_match(self, sample_npm_malicious_package):
        """Test is_finding_critical returns True when finding version matches affected versions."""
        # Use the fixture which has version="1.0.0" and affected_versions=["1.0.0"]
        assert VersionMatcher.is_finding_critical(sample_npm_malicious_package) is True
    
    def test_is_finding_critical_no_version_match(self, sample_malicious_package):
        """Test is_finding_critical returns False when finding version doesn't match affected versions."""
        # Create a modified version of the fixture with non-matching version
        from dataclasses import replace
        finding = replace(sample_malicious_package, version="2.0.0")
        
        assert VersionMatcher.is_finding_critical(finding) is False
    
    def test_is_finding_critical_no_version(self, sample_malicious_package):
        """Test is_finding_critical returns False when finding has no version."""
        from dataclasses import replace
        finding = replace(sample_malicious_package, version=None)
        
        assert VersionMatcher.is_finding_critical(finding) is False
    
    def test_is_finding_critical_no_affected_versions(self, sample_malicious_package):
        """Test is_finding_critical returns True when finding has version but no affected versions (backward compatibility)."""
        from dataclasses import replace
        finding = replace(sample_malicious_package, affected_versions=[])
        
        assert VersionMatcher.is_finding_critical(finding) is True
    
    def test_complex_version_overlap_scenario(self):
        """Test complex version overlap with multiple overlapping versions."""
        # Multiple versions in registry
        registry_versions = ["1.4.6", "2.1.1", "2.5.3", "1.8.4", "2.6.2", "2.9.0", "2.5.0"]
        # Multiple malicious versions with partial overlap
        malicious_versions = ["2.9.0", "2.10.0", "2.11.0", "2.12.0", "2.5.0", "2.6.0", "2.7.0", "2.8.0"]
        
        # Should be critical match because 2.9.0 and 2.5.0 overlap
        assert VersionMatcher.is_critical_match(registry_versions, malicious_versions) is True
        
        # Should return the overlapping versions
        expected_matches = ["2.9.0", "2.5.0"]
        actual_matches = VersionMatcher.get_matching_versions(registry_versions, malicious_versions)
        assert sorted(actual_matches) == sorted(expected_matches)
    
    def test_single_version_overlap_scenario(self):
        """Test scenario with single version overlap."""
        # Registry versions with single overlap
        registry_versions = ["2.3.0", "2.4.0"]
        # Malicious versions with one overlapping
        malicious_versions = ["2.4.0", "2.4.1"]
        
        # Should be critical match because 2.4.0 overlaps
        assert VersionMatcher.is_critical_match(registry_versions, malicious_versions) is True
        
        # Should return the overlapping version
        expected_matches = ["2.4.0"]
        actual_matches = VersionMatcher.get_matching_versions(registry_versions, malicious_versions)
        assert actual_matches == expected_matches
    
    def test_malicious_package_finding_critical(self, sample_npm_malicious_package):
        """Test malicious package finding with critical version match."""
        from dataclasses import replace
        # Create test finding using the fixture as base
        finding = replace(
            sample_npm_malicious_package,
            name="test-malicious-package",
            version="2.4.0",
            package_url="pkg:npm/test-malicious-package@2.4.0",
            affected_versions=["2.4.0", "2.4.1"]
        )
        
        # Should be critical because version 2.4.0 is in affected_versions
        assert VersionMatcher.is_finding_critical(finding) is True
    
    def test_complex_package_finding_critical(self, sample_npm_malicious_package):
        """Test complex package finding with multiple affected versions."""
        from dataclasses import replace
        # Create test finding using the fixture as base
        finding = replace(
            sample_npm_malicious_package,
            name="complex-test-package",
            version="2.9.0",
            package_url="pkg:npm/complex-test-package@2.9.0",
            affected_versions=["2.9.0", "2.10.0", "2.11.0", "2.12.0", "2.5.0", "2.6.0", "2.7.0", "2.8.0"]
        )
        
        # Should be critical because version 2.9.0 is in affected_versions
        assert VersionMatcher.is_finding_critical(finding) is True
    
    def test_scoped_package_finding_critical(self, sample_npm_malicious_package):
        """Test scoped package finding with critical version match."""
        from dataclasses import replace
        # Create scoped package finding using the fixture as base
        finding = replace(
            sample_npm_malicious_package,
            name="@test/scoped-package",
            version="2.9.0",
            package_url="pkg:npm/%40test/scoped-package@2.9.0",
            affected_versions=["2.9.0", "2.5.0"]
        )
        
        # Should be critical because version 2.9.0 is in affected_versions
        assert VersionMatcher.is_finding_critical(finding) is True