"""Unit tests for JFrog registry exclusion pattern functionality."""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from typing import List, Dict, Any

from src.providers.registries.jfrog_registry import JFrogRegistry
from src.core.entities import MaliciousPackage
from src.providers.exceptions import RegistryError


class TestJFrogRegistryExclusionPatterns:
    """Test JFrog registry exclusion pattern functionality."""
    
    @pytest.fixture
    def sample_malicious_packages(self) -> List[MaliciousPackage]:
        """Create sample malicious packages for testing."""
        return [
            MaliciousPackage(
                name="evil-npm-package",
                version="1.2.3",
                ecosystem="npm",
                package_url="pkg:npm/evil-npm-package@1.2.3",
                advisory_id="OSV-2024-001",
                summary="Malicious npm package",
                details="Contains malicious code",
                aliases=["CVE-2024-001"],
                affected_versions=["1.2.3"],
                database_specific={},
                published_at=datetime.now(),
                modified_at=datetime.now()
            ),
            MaliciousPackage(
                name="bad-python-lib",
                version=None,
                ecosystem="PyPI",
                package_url="pkg:pypi/bad-python-lib",
                advisory_id="OSV-2024-002",
                summary="Malicious PyPI package",
                details="Steals credentials",
                aliases=[],
                affected_versions=[],
                database_specific={},
                published_at=datetime.now(),
                modified_at=datetime.now()
            ),
            MaliciousPackage(
                name="@scope/malicious",
                version="2.0.0",
                ecosystem="npm",
                package_url="pkg:npm/@scope/malicious@2.0.0",
                advisory_id="OSV-2024-003",
                summary="Scoped malicious package",
                details="Supply chain attack",
                aliases=[],
                affected_versions=["2.0.0"],
                database_specific={},
                published_at=datetime.now(),
                modified_at=datetime.now()
            )
        ]
    
    @pytest.fixture
    def mock_jfrog_registry(self) -> JFrogRegistry:
        """Create JFrog registry with mocked HTTP session."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            api_key="test-key",
            repository_overrides={"npm": "npm-test", "PyPI": "pypi-test"},
            cache_ttl_seconds=300
        )
        return registry
    
    def test_ecosystem_package_type_mapping(self, mock_jfrog_registry):
        """Test ecosystem to package type mapping."""
        # Test known mappings
        assert mock_jfrog_registry._ecosystem_matches_package_type("npm", "npm")
        assert mock_jfrog_registry._ecosystem_matches_package_type("PyPI", "pypi")
        assert mock_jfrog_registry._ecosystem_matches_package_type("Maven", "maven")
        assert mock_jfrog_registry._ecosystem_matches_package_type("Go", "go")
        assert mock_jfrog_registry._ecosystem_matches_package_type("NuGet", "nuget")
        assert mock_jfrog_registry._ecosystem_matches_package_type("RubyGems", "gems")
        assert mock_jfrog_registry._ecosystem_matches_package_type("crates.io", "cargo")
        assert mock_jfrog_registry._ecosystem_matches_package_type("Packagist", "composer")
        
        # Test case insensitivity
        assert mock_jfrog_registry._ecosystem_matches_package_type("npm", "NPM")
        
        # Test mismatches
        assert not mock_jfrog_registry._ecosystem_matches_package_type("npm", "pypi")
        assert not mock_jfrog_registry._ecosystem_matches_package_type("PyPI", "maven")
        
        # Test unknown ecosystems
        assert not mock_jfrog_registry._ecosystem_matches_package_type("UnknownEcosystem", "unknown")
    
    def test_generate_exclusion_pattern_npm(self, mock_jfrog_registry, sample_malicious_packages):
        """Test exclusion pattern generation for npm packages."""
        npm_package = sample_malicious_packages[0]  # evil-npm-package
        scoped_package = sample_malicious_packages[2]  # @scope/malicious
        
        # Test regular npm package with version
        pattern = mock_jfrog_registry._generate_exclusion_pattern(npm_package)
        assert pattern == "evil-npm-package/-/evil-npm-package-1.2.3.tgz"
        
        # Test scoped npm package with version
        pattern = mock_jfrog_registry._generate_exclusion_pattern(scoped_package)
        assert pattern == "@scope/malicious/-/malicious-2.0.0.tgz"
        
        # Test npm package without version
        npm_no_version = MaliciousPackage(
            name="evil-package",
            version=None,
            ecosystem="npm",
            package_url="pkg:npm/evil-package",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=[],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(npm_no_version)
        assert pattern == "evil-package/**"
    
    def test_generate_exclusion_pattern_pypi(self, mock_jfrog_registry, sample_malicious_packages):
        """Test exclusion pattern generation for PyPI packages."""
        pypi_package = sample_malicious_packages[1]  # bad-python-lib
        
        # Test PyPI package without version
        pattern = mock_jfrog_registry._generate_exclusion_pattern(pypi_package)
        assert pattern == "simple/bad-python-lib/**"
        
        # Test PyPI package with version
        pypi_with_version = MaliciousPackage(
            name="Evil_Package",
            version="1.0.0",
            ecosystem="PyPI",
            package_url="pkg:pypi/Evil_Package@1.0.0",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(pypi_with_version)
        assert pattern == "simple/evil-package/evil-package-1.0.0*"
    
    def test_generate_exclusion_pattern_maven(self, mock_jfrog_registry):
        """Test exclusion pattern generation for Maven packages."""
        # Test Maven GAV format
        maven_package = MaliciousPackage(
            name="com.example:evil-lib:1.0.0",
            version="1.0.0",
            ecosystem="Maven",
            package_url="pkg:maven/com.example/evil-lib@1.0.0",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(maven_package)
        assert pattern == "com/example/evil-lib/1.0.0/**"
        
        # Test Maven with group:artifact only
        maven_no_version = MaliciousPackage(
            name="com.example:evil-lib",
            version="2.0.0",
            ecosystem="Maven",
            package_url="pkg:maven/com.example/evil-lib@2.0.0",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["2.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(maven_no_version)
        assert pattern == "com/example/evil-lib/2.0.0/**"
    
    def test_generate_exclusion_pattern_other_ecosystems(self, mock_jfrog_registry):
        """Test exclusion pattern generation for other ecosystems."""
        # Test Go
        go_package = MaliciousPackage(
            name="github.com/user/evil-module",
            version="v1.2.3",
            ecosystem="Go",
            package_url="pkg:golang/github.com/user/evil-module@v1.2.3",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["v1.2.3"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(go_package)
        assert pattern == "github.com/user/evil-module/@v/v1.2.3*"
        
        # Test NuGet
        nuget_package = MaliciousPackage(
            name="EvilPackage",
            version="1.0.0",
            ecosystem="NuGet",
            package_url="pkg:nuget/EvilPackage@1.0.0",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(nuget_package)
        assert pattern == "evilpackage/1.0.0/**"
        
        # Test unsupported ecosystem
        unknown_package = MaliciousPackage(
            name="unknown-package",
            version="1.0.0",
            ecosystem="UnknownEcosystem",
            package_url="pkg:unknown/unknown-package@1.0.0",
            advisory_id="TEST",
            summary="Test",
            details="",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None
        )
        pattern = mock_jfrog_registry._generate_exclusion_pattern(unknown_package)
        assert pattern == "**/unknown-package/1.0.0/**"
    
    def test_merge_exclusion_patterns(self, mock_jfrog_registry):
        """Test merging exclusion patterns."""
        # Test merging with empty current patterns
        new_patterns = ["pattern1", "pattern2"]
        result = mock_jfrog_registry._merge_exclusion_patterns("", new_patterns)
        assert result == "pattern1,pattern2"
        
        # Test merging with existing patterns
        current = "existing1,existing2"
        new_patterns = ["pattern1", "pattern2"]
        result = mock_jfrog_registry._merge_exclusion_patterns(current, new_patterns)
        # Should be sorted and deduplicated
        expected_patterns = sorted(["existing1", "existing2", "pattern1", "pattern2"])
        assert result == ",".join(expected_patterns)
        
        # Test avoiding duplicates
        current = "pattern1,existing1"
        new_patterns = ["pattern1", "pattern2"]  # pattern1 is duplicate
        result = mock_jfrog_registry._merge_exclusion_patterns(current, new_patterns)
        expected_patterns = sorted(["existing1", "pattern1", "pattern2"])
        assert result == ",".join(expected_patterns)
    
    def test_remove_patterns_from_exclusions(self, mock_jfrog_registry):
        """Test removing patterns from exclusion string."""
        # Test removing from empty patterns
        result = mock_jfrog_registry._remove_patterns_from_exclusions("", ["pattern1"])
        assert result == ""
        
        # Test removing existing patterns
        current = "pattern1,pattern2,pattern3"
        to_remove = ["pattern1", "pattern3"]
        result = mock_jfrog_registry._remove_patterns_from_exclusions(current, to_remove)
        assert result == "pattern2"
        
        # Test removing non-existent patterns
        current = "pattern1,pattern2"
        to_remove = ["pattern3", "pattern4"]
        result = mock_jfrog_registry._remove_patterns_from_exclusions(current, to_remove)
        assert result == "pattern1,pattern2"
        
        # Test removing all patterns
        current = "pattern1,pattern2"
        to_remove = ["pattern1", "pattern2"]
        result = mock_jfrog_registry._remove_patterns_from_exclusions(current, to_remove)
        assert result == ""
    
    def test_group_packages_by_ecosystem(self, mock_jfrog_registry, sample_malicious_packages):
        """Test grouping packages by ecosystem."""
        grouped = mock_jfrog_registry._group_packages_by_ecosystem(sample_malicious_packages)
        
        assert "npm" in grouped
        assert "PyPI" in grouped
        assert len(grouped["npm"]) == 2  # evil-npm-package and @scope/malicious
        assert len(grouped["PyPI"]) == 1  # bad-python-lib
        
        # Check that packages are correctly grouped
        npm_packages = grouped["npm"]
        pypi_packages = grouped["PyPI"]
        
        npm_names = [pkg.name for pkg in npm_packages]
        assert "evil-npm-package" in npm_names
        assert "@scope/malicious" in npm_names
        
        assert pypi_packages[0].name == "bad-python-lib"
    
    @pytest_asyncio.async_test
    async def test_repository_override_functionality(self):
        """Test repository override functionality."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            api_key="test-key",
            repository_overrides={"npm": "override-npm-repo"},
            cache_ttl_seconds=300
        )
        
        # Should return override without making API call
        repos = await registry.discover_repositories_by_ecosystem("npm")
        assert repos == ["override-npm-repo"]
        
        # Cache should remain empty since we used override
        assert "npm" not in registry._repository_cache
        
        await registry.close()
    
    @pytest_asyncio.async_test
    async def test_health_check_success(self):
        """Test successful health check."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            api_key="test-key"
        )
        
        # Mock the session and response
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="OK")
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        registry._session = mock_session
        
        result = await registry.health_check()
        assert result is True
        
        # Verify the correct endpoint was called
        mock_session.get.assert_called_once_with("https://test.jfrog.io/artifactory/api/system/ping")
        
        await registry.close()
    
    @pytest_asyncio.async_test
    async def test_health_check_failure(self):
        """Test failed health check."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            api_key="test-key"
        )
        
        # Mock the session and response with error
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        registry._session = mock_session
        
        result = await registry.health_check()
        assert result is False
        
        await registry.close()
    
    def test_authentication_headers_api_key(self):
        """Test authentication headers with API key."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            api_key="test-api-key"
        )
        
        headers = registry._get_auth_headers()
        assert headers["Authorization"] == "Bearer test-api-key"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
    
    def test_authentication_headers_basic_auth(self):
        """Test authentication headers with username/password."""
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io",
            username="testuser",
            password="testpass"
        )
        
        headers = registry._get_auth_headers()
        
        # Should use Basic auth
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        
        # Decode and verify credentials
        import base64
        encoded_creds = headers["Authorization"].split(" ")[1]
        decoded_creds = base64.b64decode(encoded_creds).decode()
        assert decoded_creds == "testuser:testpass"
    
    def test_invalid_authentication(self):
        """Test that invalid authentication raises error."""
        with pytest.raises(ValueError, match="Either api_key or username/password must be provided"):
            JFrogRegistry(base_url="https://test.jfrog.io")
    
    def test_registry_name(self, mock_jfrog_registry):
        """Test registry name property."""
        assert mock_jfrog_registry.get_registry_name() == "JFrog Artifactory"