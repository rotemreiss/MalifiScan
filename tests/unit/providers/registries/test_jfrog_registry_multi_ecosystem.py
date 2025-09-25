"""Unit tests for JFrog registry multi-ecosystem support."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, Optional

from src.providers.registries.jfrog_registry import JFrogRegistry
from src.core.entities import MaliciousPackage


def create_test_malicious_package(name: str, ecosystem: str, version: Optional[str] = None, advisory_id: Optional[str] = None) -> MaliciousPackage:
    """Helper function to create test MaliciousPackage instances with required fields."""
    return MaliciousPackage(
        name=name,
        ecosystem=ecosystem,
        version=version,
        advisory_id=advisory_id or "MAL-001",
        package_url=f"pkg:{ecosystem.lower()}/{name}@{version}" if version else f"pkg:{ecosystem.lower()}/{name}",
        summary=f"Malicious {ecosystem} package",
        details="Test details",
        aliases=[],
        affected_versions=[version] if version else [],
        database_specific={},
        published_at=None,
        modified_at=None
    )


class TestJFrogRegistryMultiEcosystem:
    """Test JFrog registry multi-ecosystem functionality."""
    
    @pytest.fixture
    def jfrog_registry(self):
        """Create JFrog registry instance."""
        return JFrogRegistry(
            base_url="https://test.jfrog.io/artifactory",
            api_key="test-api-key"
        )
    
    @pytest.mark.asyncio
    async def test_get_supported_ecosystems(self, jfrog_registry):
        """Test getting list of supported ecosystems."""
        ecosystems = await jfrog_registry.get_supported_ecosystems()
        
        expected_ecosystems = [
            "npm", "PyPI", "Maven", "Go", "NuGet", 
            "RubyGems", "crates.io", "Packagist", "Pub", "Hex"
        ]
        
        assert ecosystems == expected_ecosystems
    
    def test_ecosystem_matches_package_type_all_supported(self, jfrog_registry):
        """Test ecosystem to package type matching for all supported ecosystems."""
        test_cases = [
            ("npm", "npm", True),
            ("PyPI", "pypi", True),
            ("Maven", "maven", True),
            ("Go", "go", True),
            ("NuGet", "nuget", True),
            ("RubyGems", "gems", True),
            ("crates.io", "cargo", True),
            ("Packagist", "composer", True),
            ("Pub", "generic", True),
            ("Hex", "generic", True),
            ("npm", "pypi", False),  # Wrong match
            ("UnknownEcosystem", "unknown", False),  # Unsupported ecosystem
        ]
        
        for ecosystem, package_type, expected in test_cases:
            result = jfrog_registry._ecosystem_matches_package_type(ecosystem, package_type)
            assert result == expected, f"Failed for {ecosystem} -> {package_type}"
    
    def test_get_ecosystem_blocking_support_full_support(self, jfrog_registry):
        """Test blocking support for ecosystems with full support."""
        full_support_ecosystems = ["npm", "PyPI", "Maven", "Go", "NuGet"]
        
        for ecosystem in full_support_ecosystems:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            
            assert support["scanning"] is True
            assert support["blocking"] is True
            assert support["pattern_quality"] == "full"
    
    def test_get_ecosystem_blocking_support_basic_support(self, jfrog_registry):
        """Test blocking support for ecosystems with basic support."""
        basic_support_ecosystems = ["RubyGems", "crates.io", "Packagist"]
        
        for ecosystem in basic_support_ecosystems:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            
            assert support["scanning"] is True
            assert support["blocking"] is True
            assert support["pattern_quality"] == "basic"
    
    def test_get_ecosystem_blocking_support_limited_support(self, jfrog_registry):
        """Test blocking support for ecosystems with limited support."""
        limited_support_ecosystems = ["Pub", "Hex"]
        
        for ecosystem in limited_support_ecosystems:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            
            assert support["scanning"] is True
            assert support["blocking"] is False
            assert support["pattern_quality"] == "none"
    
    def test_get_ecosystem_blocking_support_unsupported(self, jfrog_registry):
        """Test blocking support for unsupported ecosystems."""
        unsupported_ecosystems = ["UnknownEcosystem", "CustomPackages"]
        
        for ecosystem in unsupported_ecosystems:
            support = jfrog_registry.get_ecosystem_blocking_support(ecosystem)
            
            assert support["scanning"] is False
            assert support["blocking"] is False
            assert support["pattern_quality"] == "none"
    
    def test_generate_exclusion_pattern_npm(self, jfrog_registry):
        """Test NPM exclusion pattern generation."""
        # Regular NPM package
        npm_package = create_test_malicious_package("axios", "npm", "1.0.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(npm_package)
        assert pattern == "axios/-/axios-1.0.0.tgz"
        
        # Scoped NPM package
        scoped_package = create_test_malicious_package("@angular/core", "npm", "12.0.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(scoped_package)
        assert pattern == "@angular/core/-/core-12.0.0.tgz"
        
        # NPM package without version
        no_version_package = create_test_malicious_package("lodash", "npm", None)
        
        pattern = jfrog_registry._generate_exclusion_pattern(no_version_package)
        assert pattern == "lodash/**"
    
    def test_generate_exclusion_pattern_pypi(self, jfrog_registry):
        """Test PyPI exclusion pattern generation."""
        # PyPI package with version
        pypi_package = create_test_malicious_package("Django", "PyPI", "3.2.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(pypi_package)
        assert pattern == "simple/django/django-3.2.0*"
        
        # PyPI package without version
        no_version_package = create_test_malicious_package("Flask_Security", "PyPI", None)
        
        pattern = jfrog_registry._generate_exclusion_pattern(no_version_package)
        assert pattern == "simple/flask-security/**"
    
    def test_generate_exclusion_pattern_maven(self, jfrog_registry):
        """Test Maven exclusion pattern generation."""
        # Maven package with GAV format
        maven_package = create_test_malicious_package("com.fasterxml.jackson.core:jackson-core", "Maven", "2.12.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(maven_package)
        assert pattern == "com/fasterxml/jackson/core/jackson-core/2.12.0/**"
        
        # Maven package without version
        no_version_package = create_test_malicious_package("org.springframework:spring-core", "Maven", None)
        
        pattern = jfrog_registry._generate_exclusion_pattern(no_version_package)
        assert pattern == "org/springframework/spring-core/**"
    
    def test_generate_exclusion_pattern_go(self, jfrog_registry):
        """Test Go exclusion pattern generation."""
        go_package = create_test_malicious_package("github.com/gorilla/mux", "Go", "v1.8.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(go_package)
        assert pattern == "github.com/gorilla/mux/@v/v1.8.0*"
    
    def test_generate_exclusion_pattern_nuget(self, jfrog_registry):
        """Test NuGet exclusion pattern generation."""
        nuget_package = create_test_malicious_package("Newtonsoft.Json", "NuGet", "13.0.1")
        
        pattern = jfrog_registry._generate_exclusion_pattern(nuget_package)
        assert pattern == "newtonsoft.json/13.0.1/**"
    
    def test_generate_exclusion_pattern_rubygems(self, jfrog_registry):
        """Test RubyGems exclusion pattern generation."""
        rubygems_package = create_test_malicious_package("rails", "RubyGems", "7.0.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(rubygems_package)
        assert pattern == "gems/rails-7.0.0.gem"
    
    def test_generate_exclusion_pattern_crates(self, jfrog_registry):
        """Test crates.io exclusion pattern generation."""
        crates_package = create_test_malicious_package("serde", "crates.io", "1.0.136")
        
        pattern = jfrog_registry._generate_exclusion_pattern(crates_package)
        assert pattern == "crates/serde/serde-1.0.136.crate"
    
    def test_generate_exclusion_pattern_packagist(self, jfrog_registry):
        """Test Packagist exclusion pattern generation."""
        # Vendor/package format
        packagist_package = create_test_malicious_package("symfony/console", "Packagist", "5.3.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(packagist_package)
        assert pattern == "symfony/console/5.3.0/**"
        
        # Package without vendor
        simple_package = create_test_malicious_package("monolog", "Packagist", "2.3.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(simple_package)
        assert pattern == "**/monolog/2.3.0/**"
    
    def test_generate_exclusion_pattern_pub_hex_limited_support(self, jfrog_registry, caplog):
        """Test that Pub and Hex patterns generate warnings about limited support."""
        # Pub package
        pub_package = create_test_malicious_package("flutter_test", "Pub", "1.0.0")
        
        pattern = jfrog_registry._generate_exclusion_pattern(pub_package)
        assert pattern == "**/flutter_test-1.0.0*"
        assert "Pub/Dart ecosystem has limited blocking support" in caplog.text
        
        # Hex package
        hex_package = create_test_malicious_package("phoenix", "Hex", "1.6.0")
        
        caplog.clear()
        pattern = jfrog_registry._generate_exclusion_pattern(hex_package)
        assert pattern == "**/phoenix-1.6.0*"
        assert "Hex/Elixir ecosystem has limited blocking support" in caplog.text
    
    def test_get_repository_name_all_ecosystems(self, jfrog_registry):
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
            assert repo_name == expected_repo
        
        # Test unsupported ecosystem
        assert jfrog_registry._get_repository_name("UnknownEcosystem") is None
    
    @pytest.mark.asyncio
    async def test_discover_repositories_by_ecosystem_multi_ecosystem(self, jfrog_registry):
        """Test repository discovery for multiple ecosystems."""
        # Mock the method to return specific repositories for each ecosystem
        async def mock_discover_repos(ecosystem):
            mock_data = {
                "npm": ["npm-local", "npm-remote"],
                "PyPI": ["pypi-virtual"],  
                "Maven": ["maven-central"],
                "UnknownEcosystem": []
            }
            return mock_data.get(ecosystem, [])
        
        with patch.object(jfrog_registry, 'discover_repositories_by_ecosystem', side_effect=mock_discover_repos):
            # Test npm repositories
            npm_repos = await jfrog_registry.discover_repositories_by_ecosystem("npm")
            assert set(npm_repos) == {"npm-local", "npm-remote"}
            
            # Test PyPI repositories
            pypi_repos = await jfrog_registry.discover_repositories_by_ecosystem("PyPI")
            assert pypi_repos == ["pypi-virtual"]
            
            # Test Maven repositories  
            maven_repos = await jfrog_registry.discover_repositories_by_ecosystem("Maven")
            assert maven_repos == ["maven-central"]
            
            # Test unsupported ecosystem
            unknown_repos = await jfrog_registry.discover_repositories_by_ecosystem("UnknownEcosystem")
            assert unknown_repos == []