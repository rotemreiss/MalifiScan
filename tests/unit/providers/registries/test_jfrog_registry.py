"""
Unit tests for JFrog registry provider.
Comprehensive test suite covering version extraction and multi-ecosystem functionality.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, Optional

from src.providers.registries.jfrog_registry import JFrogRegistry
from src.core.entities import MaliciousPackage


@pytest.fixture
def jfrog_registry():
    """Create a JFrogRegistry instance for testing."""
    return JFrogRegistry(
        base_url='https://test.jfrog.io/artifactory',
        username='test_user',
        api_key='test-api-key'
    )


@pytest.fixture
def test_package_data():
    """Test package data for various ecosystems."""
    return {
        'npm_regular': ('axios', 'npm', '1.0.0'),
        'npm_scoped': ('@angular/core', 'npm', '12.0.0'),
        'npm_no_version': ('lodash', 'npm', None),
        'pypi_regular': ('Django', 'PyPI', '3.2.0'),
        'pypi_underscore': ('Flask_Security', 'PyPI', None),
        'maven_gav': ('com.fasterxml.jackson.core:jackson-core', 'Maven', '2.12.0'),
        'maven_no_version': ('org.springframework:spring-core', 'Maven', None),
        'go_module': ('github.com/gorilla/mux', 'Go', 'v1.8.0'),
        'nuget_package': ('Newtonsoft.Json', 'NuGet', '13.0.1'),
        'rubygems_package': ('rails', 'RubyGems', '7.0.0'),
        'crates_package': ('serde', 'crates.io', '1.0.136'),
        'packagist_vendor': ('symfony/console', 'Packagist', '5.3.0'),
        'packagist_simple': ('monolog', 'Packagist', '2.3.0'),
        'pub_package': ('flutter_test', 'Pub', '1.0.0'),
        'hex_package': ('phoenix', 'Hex', '1.6.0'),
    }


def create_test_package(name: str, ecosystem: str, version: Optional[str] = None, advisory_id: Optional[str] = None) -> MaliciousPackage:
    """
    Helper function to create test MaliciousPackage instances.
    Uses conftest.py patterns but allows customization for specific test scenarios.
    """
    return MaliciousPackage(
        name=name,
        ecosystem=ecosystem,
        version=version,
        advisory_id=advisory_id or "TEST-001",
        package_url=f"pkg:{ecosystem.lower()}/{name}@{version}" if version else f"pkg:{ecosystem.lower()}/{name}",
        summary=f"Test {ecosystem} package",
        details="Test package for unit testing",
        aliases=[],
        affected_versions=[version] if version else [],
        database_specific={},
        published_at=None,
        modified_at=None
    )


class TestJFrogVersionExtraction:
    """Test suite for JFrog registry version extraction functionality."""
    
    def test_exact_package_name_version_extraction(self, jfrog_registry):
        """Test version extraction for exact package name matches."""
        version = jfrog_registry._extract_version_from_filename(
            "test-package-1.0.0.json", "test-package", "npm"
        )
        assert version == "1.0.0"
        
        # Different package names should fall back to other patterns
        version = jfrog_registry._extract_version_from_filename(
            "other-package-1.0.0.json", "test-package", "npm"
        )
        assert version == "1.0.0"  # Should extract via fallback patterns
    
    def test_compound_package_name_version_extraction(self, jfrog_registry):
        """Test version extraction for compound package names containing the search term."""
        version = jfrog_registry._extract_version_from_filename(
            "test-package-webpack-plugin-2.4.0.json", 
            "test-package", 
            "npm"
        )
        assert version == "2.4.0"
        
        # Should still work for exact matches
        version = jfrog_registry._extract_version_from_filename(
            "test-package-1.0.0.json", 
            "test-package", 
            "npm"
        )
        assert version == "1.0.0"
    
    def test_generic_version_extraction(self, jfrog_registry):
        """Test generic version extraction from any npm package filename."""
        test_cases = [
            ("any-package-name-1.2.3.json", "1.2.3"),
            ("complex-package-name-2.0.0-beta.json", "2.0.0-beta"),
            ("@scoped/package-3.1.4.json", "3.1.4"),
        ]
        
        for filename, expected_version in test_cases:
            version = jfrog_registry._extract_version_from_filename(
                filename, "any-package", "npm"
            )
            assert version == expected_version, f"Expected {expected_version}, got {version} from {filename}"
    
    def test_json_suffix_cleanup(self, jfrog_registry):
        """Test that .json suffixes are properly cleaned from extracted versions."""
        test_cases = [
            ("package-1.0.0.json", "1.0.0"),
            ("package-2.1.3-beta.json", "2.1.3-beta"),
            ("complex-name-3.0.0-alpha.1.json", "3.0.0-alpha.1"),
        ]
        
        for filename, expected_version in test_cases:
            version = jfrog_registry._extract_version_from_filename(
                filename, "package", "npm"
            )
            assert version == expected_version
            assert not version.endswith('.json'), f"Version should not end with .json: {version}"
    
    def test_no_match_scenarios(self, jfrog_registry):
        """Test scenarios where no version should be extracted."""
        no_match_cases = [
            "package-without-version.json",  # No semantic version
            "package.json",  # Just package.json
            "README.md",  # Non-npm file
            "",  # Empty filename
        ]
        
        for filename in no_match_cases:
            version = jfrog_registry._extract_version_from_filename(
                filename, "package", "npm"
            )
            assert version == "", f"Expected empty string for {filename}, got {version}"
    
    def test_non_npm_ecosystem(self, jfrog_registry):
        """Test that non-npm ecosystems return empty string (not implemented yet)."""
        version = jfrog_registry._extract_version_from_filename(
            "some-file-1.0.0.whl", "package", "PyPI"
        )
        assert version == "", "Non-npm ecosystems should return empty string"
    
    def test_real_world_scenarios(self, jfrog_registry):
        """Test real-world version extraction scenarios."""
        real_world_cases = [
            # Compound plugin package scenario
            ("test-package-webpack-plugin-2.4.0.json", "test-package", "2.4.0"),
            # Common packages
            ("test-lib-21.5.0.json", "test-lib", "21.5.0"),
            ("@test/workspace-21.5.0.json", "@test/workspace", "21.5.0"),
            ("@test/eslint-21.5.0.json", "@test/eslint", "21.5.0"),
        ]
        
        for filename, package_name, expected_version in real_world_cases:
            version = jfrog_registry._extract_version_from_filename(
                filename, package_name, "npm"
            )
            assert version == expected_version, f"Expected {expected_version}, got {version} from {filename}"
    
    def test_complex_version_patterns(self, jfrog_registry):
        """Test complex version patterns with pre-release, build metadata, etc."""
        test_cases = [
            ("package-1.0.0-alpha.json", "1.0.0-alpha"),
            ("package-1.0.0-beta.1.json", "1.0.0-beta.1"),
            ("package-1.0.0-rc.2.json", "1.0.0-rc.2"),
            ("package-2.0.0-next.1.json", "2.0.0-next.1"),
        ]
        
        for filename, expected_version in test_cases:
            version = jfrog_registry._extract_version_from_filename(
                filename, "package", "npm"
            )
            assert version == expected_version, f"Expected {expected_version}, got {version} from {filename}"


class TestJFrogMultiEcosystem:
    """Test suite for JFrog registry multi-ecosystem functionality."""
    
    @pytest.mark.asyncio
    async def test_get_supported_ecosystems(self, jfrog_registry):
        """Test getting list of supported ecosystems."""
        ecosystems = await jfrog_registry.get_supported_ecosystems()
        
        expected_ecosystems = [
            "npm", "PyPI", "Maven", "Go", "NuGet", 
            "RubyGems", "crates.io", "Packagist", "Pub", "Hex"
        ]
        
        assert ecosystems == expected_ecosystems
    
    def test_ecosystem_matches_package_type(self, jfrog_registry):
        """Test ecosystem to package type matching for all supported ecosystems."""
        ecosystem_mapping = {
            ("npm", "npm"): True,
            ("PyPI", "pypi"): True,
            ("Maven", "maven"): True,
            ("Go", "go"): True,
            ("NuGet", "nuget"): True,
            ("RubyGems", "gems"): True,
            ("crates.io", "cargo"): True,
            ("Packagist", "composer"): True,
            ("Pub", "generic"): True,
            ("Hex", "generic"): True,
            ("npm", "pypi"): False,  # Wrong match
            ("UnknownEcosystem", "unknown"): False,  # Unsupported ecosystem
        }
        
        for (ecosystem, package_type), expected in ecosystem_mapping.items():
            result = jfrog_registry._ecosystem_matches_package_type(ecosystem, package_type)
            assert result == expected, f"Failed for {ecosystem} -> {package_type}"
    
    def test_ecosystem_blocking_support_levels(self, jfrog_registry):
        """Test blocking support for different ecosystem categories."""
        # Full support ecosystems
        full_support = ["npm", "PyPI", "Maven", "Go", "NuGet"]
        for ecosystem in full_support:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is True
            assert support["blocking"] is True
            assert support["pattern_quality"] == "full"
        
        # Basic support ecosystems
        basic_support = ["RubyGems", "crates.io", "Packagist"]
        for ecosystem in basic_support:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is True
            assert support["blocking"] is True
            assert support["pattern_quality"] == "basic"
        
        # Limited support ecosystems
        limited_support = ["Pub", "Hex"]
        for ecosystem in limited_support:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is True
            assert support["blocking"] is False
            assert support["pattern_quality"] == "none"
        
        # Unsupported ecosystems
        unsupported = ["UnknownEcosystem", "CustomPackages"]
        for ecosystem in unsupported:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            assert support["scanning"] is False
            assert support["blocking"] is False
            assert support["pattern_quality"] == "none"
    
    def test_exclusion_pattern_generation(self, jfrog_registry, test_package_data):
        """Test exclusion pattern generation for all ecosystems."""
        expected_patterns = {
            # NPM patterns
            'npm_regular': "axios/-/axios-1.0.0.tgz",
            'npm_scoped': "@angular/core/-/core-12.0.0.tgz",
            'npm_no_version': "lodash/**",
            
            # PyPI patterns  
            'pypi_regular': "simple/django/django-3.2.0*",
            'pypi_underscore': "simple/flask-security/**",
            
            # Maven patterns
            'maven_gav': "com/fasterxml/jackson/core/jackson-core/2.12.0/**",
            'maven_no_version': "org/springframework/spring-core/**",
            
            # Other ecosystem patterns
            'go_module': "github.com/gorilla/mux/@v/v1.8.0*",
            'nuget_package': "newtonsoft.json/13.0.1/**",
            'rubygems_package': "gems/rails-7.0.0.gem",
            'crates_package': "crates/serde/serde-1.0.136.crate",
            'packagist_vendor': "symfony/console/5.3.0/**",
            'packagist_simple': "**/monolog/2.3.0/**",
            'pub_package': "**/flutter_test-1.0.0*",
            'hex_package': "**/phoenix-1.6.0*",
        }
        
        for package_key, expected_pattern in expected_patterns.items():
            name, ecosystem, version = test_package_data[package_key]
            test_package = create_test_package(name, ecosystem, version)
            
            pattern = jfrog_registry._generate_exclusion_pattern(test_package)
            assert pattern == expected_pattern, f"Failed for {package_key}: expected {expected_pattern}, got {pattern}"
    
    def test_limited_support_ecosystem_warnings(self, jfrog_registry, caplog):
        """Test that Pub and Hex patterns generate warnings about limited support."""
        # Test Pub package
        pub_package = create_test_package("flutter_test", "Pub", "1.0.0")
        pattern = jfrog_registry._generate_exclusion_pattern(pub_package)
        assert pattern == "**/flutter_test-1.0.0*"
        assert "Pub/Dart ecosystem has limited blocking support" in caplog.text
        
        # Test Hex package
        caplog.clear()
        hex_package = create_test_package("phoenix", "Hex", "1.6.0")
        pattern = jfrog_registry._generate_exclusion_pattern(hex_package)
        assert pattern == "**/phoenix-1.6.0*"
        assert "Hex/Elixir ecosystem has limited blocking support" in caplog.text
    
    def test_repository_name_mapping(self, jfrog_registry):
        """Test repository name mapping for all ecosystems."""
        expected_mappings = {
            "PyPI": "pypi-remote",
            "npm": "npm-remote",
            "Maven": "maven-remote", 
            "Go": "go-remote",
            "NuGet": "nuget-remote",
            "RubyGems": "gems-remote",
            "crates.io": "cargo-remote",
            "Packagist": "composer-remote",
            "Pub": "generic-remote",
            "Hex": "generic-remote"
        }
        
        for ecosystem, expected_repo in expected_mappings.items():
            repo_name = jfrog_registry._get_repository_name(ecosystem)
            assert repo_name == expected_repo, f"Failed for {ecosystem}: expected {expected_repo}, got {repo_name}"
        
        # Test unsupported ecosystem
        assert jfrog_registry._get_repository_name("UnknownEcosystem") is None
    
    @pytest.mark.asyncio
    async def test_repository_discovery_multi_ecosystem(self, jfrog_registry):
        """Test repository discovery for multiple ecosystems."""
        async def mock_discover_repos(ecosystem):
            """Mock repository discovery with realistic data."""
            mock_data = {
                "npm": ["npm-local", "npm-remote"],
                "PyPI": ["pypi-virtual"],  
                "Maven": ["maven-central"],
                "UnknownEcosystem": []
            }
            return mock_data.get(ecosystem, [])
        
        with patch.object(jfrog_registry, 'discover_repositories_by_ecosystem', side_effect=mock_discover_repos):
            # Test various ecosystems
            npm_repos = await jfrog_registry.discover_repositories_by_ecosystem("npm")
            assert set(npm_repos) == {"npm-local", "npm-remote"}
            
            pypi_repos = await jfrog_registry.discover_repositories_by_ecosystem("PyPI")
            assert pypi_repos == ["pypi-virtual"]
            
            maven_repos = await jfrog_registry.discover_repositories_by_ecosystem("Maven")
            assert maven_repos == ["maven-central"]
            
            unknown_repos = await jfrog_registry.discover_repositories_by_ecosystem("UnknownEcosystem")
            assert unknown_repos == []


class TestJFrogRegistryCore:
    """Test suite for core JFrog registry functionality using existing patterns."""
    
    def test_registry_initialization(self):
        """Test JFrog registry initialization with various configurations."""
        # Test with API key
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io/artifactory",
            api_key="test-key"
        )
        assert registry.base_url == "https://test.jfrog.io/artifactory"
        assert registry.api_key == "test-key"
        
        # Test with username/password
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io/artifactory",
            username="user",
            password="pass"
        )
        assert registry.username == "user"
        assert registry.password == "pass"
    
    def test_registry_name(self, jfrog_registry):
        """Test registry name retrieval."""
        name = jfrog_registry.get_registry_name()
        assert "JFrog" in name or "Artifactory" in name
    
    @pytest.mark.asyncio
    async def test_health_check(self, jfrog_registry):
        """Test health check functionality."""
        # Mock the health check to return True
        with patch.object(jfrog_registry, 'health_check', return_value=True):
            health = await jfrog_registry.health_check()
            assert health is True