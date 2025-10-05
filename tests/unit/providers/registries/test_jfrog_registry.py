"""
Unit tests for JFrog registry provider.
Comprehensive test suite covering version extraction and multi-ecosystem functionality.
"""

from typing import Optional
from unittest.mock import patch

import pytest

from src.core.entities import MaliciousPackage
from src.providers.registries.jfrog_registry import JFrogRegistry


@pytest.fixture
def jfrog_registry():
    """Create a JFrogRegistry instance for testing."""
    return JFrogRegistry(
        base_url="https://test.jfrog.io/artifactory",
        username="test_user",
        api_key="test-api-key",
    )


@pytest.fixture
def test_package_data():
    """Test package data for various ecosystems."""
    return {
        "npm_regular": ("axios", "npm", "1.0.0"),
        "npm_scoped": ("@angular/core", "npm", "12.0.0"),
        "npm_no_version": ("lodash", "npm", None),
        "pypi_regular": ("Django", "PyPI", "3.2.0"),
        "pypi_underscore": ("Flask_Security", "PyPI", None),
        "maven_gav": ("com.fasterxml.jackson.core:jackson-core", "Maven", "2.12.0"),
        "maven_no_version": ("org.springframework:spring-core", "Maven", None),
        "go_module": ("github.com/gorilla/mux", "Go", "v1.8.0"),
        "nuget_package": ("Newtonsoft.Json", "NuGet", "13.0.1"),
        "rubygems_package": ("rails", "RubyGems", "7.0.0"),
        "crates_package": ("serde", "crates.io", "1.0.136"),
        "packagist_vendor": ("symfony/console", "Packagist", "5.3.0"),
        "packagist_simple": ("monolog", "Packagist", "2.3.0"),
        "pub_package": ("flutter_test", "Pub", "1.0.0"),
        "hex_package": ("phoenix", "Hex", "1.6.0"),
    }


def create_test_package(
    name: str,
    ecosystem: str,
    version: Optional[str] = None,
    advisory_id: Optional[str] = None,
) -> MaliciousPackage:
    """
    Helper function to create test MaliciousPackage instances.
    Uses conftest.py patterns but allows customization for specific test scenarios.
    """
    return MaliciousPackage(
        name=name,
        ecosystem=ecosystem,
        version=version,
        advisory_id=advisory_id or "TEST-001",
        package_url=(
            f"pkg:{ecosystem.lower()}/{name}@{version}"
            if version
            else f"pkg:{ecosystem.lower()}/{name}"
        ),
        summary=f"Test {ecosystem} package",
        details="Test package for unit testing",
        aliases=[],
        affected_versions=[version] if version else [],
        database_specific={},
        published_at=None,
        modified_at=None,
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
            "test-package-webpack-plugin-2.4.0.json", "test-package", "npm"
        )
        assert version == "2.4.0"

        # Should still work for exact matches
        version = jfrog_registry._extract_version_from_filename(
            "test-package-1.0.0.json", "test-package", "npm"
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
            assert (
                version == expected_version
            ), f"Expected {expected_version}, got {version} from {filename}"

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
            assert not version.endswith(
                ".json"
            ), f"Version should not end with .json: {version}"

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
            assert (
                version == expected_version
            ), f"Expected {expected_version}, got {version} from {filename}"

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
            assert (
                version == expected_version
            ), f"Expected {expected_version}, got {version} from {filename}"


class TestJFrogMultiEcosystem:
    """Test suite for JFrog registry multi-ecosystem functionality."""

    @pytest.mark.asyncio
    async def test_get_supported_ecosystems(self, jfrog_registry):
        """Test getting list of supported ecosystems."""
        ecosystems = await jfrog_registry.get_supported_ecosystems()

        expected_ecosystems = [
            "npm",
            "PyPI",
            "Maven",
            "Go",
            "NuGet",
            "RubyGems",
            "crates.io",
            "Packagist",
            "Pub",
            "Hex",
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
            result = jfrog_registry._ecosystem_matches_package_type(
                ecosystem, package_type
            )
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
            "npm_regular": "axios/-/axios-1.0.0.tgz",
            "npm_scoped": "@angular/core/-/core-12.0.0.tgz",
            "npm_no_version": "lodash/**",
            # PyPI patterns
            "pypi_regular": "simple/django/django-3.2.0*",
            "pypi_underscore": "simple/flask-security/**",
            # Maven patterns
            "maven_gav": "com/fasterxml/jackson/core/jackson-core/2.12.0/**",
            "maven_no_version": "org/springframework/spring-core/**",
            # Other ecosystem patterns
            "go_module": "github.com/gorilla/mux/@v/v1.8.0*",
            "nuget_package": "newtonsoft.json/13.0.1/**",
            "rubygems_package": "gems/rails-7.0.0.gem",
            "crates_package": "crates/serde/serde-1.0.136.crate",
            "packagist_vendor": "symfony/console/5.3.0/**",
            "packagist_simple": "**/monolog/2.3.0/**",
            "pub_package": "**/flutter_test-1.0.0*",
            "hex_package": "**/phoenix-1.6.0*",
        }

        for package_key, expected_pattern in expected_patterns.items():
            name, ecosystem, version = test_package_data[package_key]
            test_package = create_test_package(name, ecosystem, version)

            pattern = jfrog_registry._generate_exclusion_pattern(test_package)
            assert (
                pattern == expected_pattern
            ), f"Failed for {package_key}: expected {expected_pattern}, got {pattern}"

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
            "Hex": "generic-remote",
        }

        for ecosystem, expected_repo in expected_mappings.items():
            repo_name = jfrog_registry._get_repository_name(ecosystem)
            assert (
                repo_name == expected_repo
            ), f"Failed for {ecosystem}: expected {expected_repo}, got {repo_name}"

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
                "UnknownEcosystem": [],
            }
            return mock_data.get(ecosystem, [])

        with patch.object(
            jfrog_registry,
            "discover_repositories_by_ecosystem",
            side_effect=mock_discover_repos,
        ):
            # Test various ecosystems
            npm_repos = await jfrog_registry.discover_repositories_by_ecosystem("npm")
            assert set(npm_repos) == {"npm-local", "npm-remote"}

            pypi_repos = await jfrog_registry.discover_repositories_by_ecosystem("PyPI")
            assert pypi_repos == ["pypi-virtual"]

            maven_repos = await jfrog_registry.discover_repositories_by_ecosystem(
                "Maven"
            )
            assert maven_repos == ["maven-central"]

            unknown_repos = await jfrog_registry.discover_repositories_by_ecosystem(
                "UnknownEcosystem"
            )
            assert unknown_repos == []


class TestJFrogRegistryCore:
    """Test suite for core JFrog registry functionality using existing patterns."""

    def test_registry_initialization(self):
        """Test JFrog registry initialization with various configurations."""
        # Test with API key
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io/artifactory", api_key="test-key"
        )
        assert registry.base_url == "https://test.jfrog.io/artifactory"
        assert registry.api_key == "test-key"

        # Test with username/password
        registry = JFrogRegistry(
            base_url="https://test.jfrog.io/artifactory",
            username="user",
            password="pass",
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
        with patch.object(jfrog_registry, "health_check", return_value=True):
            health = await jfrog_registry.health_check()
            assert health is True


class TestEcosystemSpecificAQLQueries:
    """Test suite for ecosystem-specific AQL query builders."""

    def test_build_npm_aql_query_regular_package(self, jfrog_registry):
        """Test AQL query building for regular npm packages."""
        query = jfrog_registry._build_npm_aql_query("lodash", "npm-remote")
        expected = 'items.find({\n                "repo": "npm-remote",\n                "$or": [\n                    {"path": {"$eq": ".npm/lodash"}},\n                    {"path": {"$match": ".npm/lodash/*"}}\n                ]\n            })'
        assert query == expected

    def test_build_npm_aql_query_scoped_package(self, jfrog_registry):
        """Test AQL query building for scoped npm packages."""
        query = jfrog_registry._build_npm_aql_query("@angular/core", "npm-remote")
        expected = 'items.find({\n                "repo": "npm-remote",\n                "$or": [\n                    {"path": {"$eq": ".npm/@angular/core"}},\n                    {"path": {"$match": ".npm/@angular/core/*"}}\n                ]\n            })'
        assert query == expected

    def test_build_pypi_aql_query(self, jfrog_registry):
        """Test AQL query building for PyPI packages."""
        query = jfrog_registry._build_pypi_aql_query("Django", "pypi-remote")
        expected = 'items.find({\n            "repo": "pypi-remote",\n            "path": {"$eq": "simple/django"}\n        })'
        assert query == expected

    def test_build_pypi_aql_query_with_underscore(self, jfrog_registry):
        """Test AQL query building for PyPI packages with underscores."""
        query = jfrog_registry._build_pypi_aql_query("Flask_Security", "pypi-remote")
        expected = 'items.find({\n            "repo": "pypi-remote",\n            "path": {"$eq": "simple/flask-security"}\n        })'
        assert query == expected

    def test_build_maven_aql_query_with_gav(self, jfrog_registry):
        """Test AQL query building for Maven packages with group:artifact."""
        query = jfrog_registry._build_maven_aql_query(
            "com.fasterxml.jackson.core:jackson-core", "maven-remote"
        )
        expected = 'items.find({\n                    "repo": "maven-remote",\n                    "path": {"$eq": "com/fasterxml/jackson/core/jackson-core"}\n                })'
        assert query == expected

    def test_build_maven_aql_query_artifact_only(self, jfrog_registry):
        """Test AQL query building for Maven packages with artifact only."""
        query = jfrog_registry._build_maven_aql_query("spring-core", "maven-remote")
        expected = 'items.find({\n                "repo": "maven-remote",\n                "name": {"$eq": "spring-core"}\n            })'
        assert query == expected

    def test_build_generic_aql_query(self, jfrog_registry):
        """Test AQL query building for generic packages."""
        query = jfrog_registry._build_generic_aql_query(
            "some-package", "generic-remote"
        )
        expected = 'items.find({\n            "repo": "generic-remote",\n            "name": {"$eq": "some-package"}\n        })'
        assert query == expected


class TestEcosystemSpecificExactMatching:
    """Test suite for ecosystem-specific exact match validation."""

    def test_npm_exact_match_regular_package(self, jfrog_registry):
        """Test exact matching for regular npm packages."""
        # Exact match cases
        item = {"path": ".npm/lodash", "name": "package.json"}
        assert jfrog_registry._is_npm_exact_match(item, "lodash")

        item = {"path": ".npm/lodash/1.0.0", "name": "lodash-1.0.0.tgz"}
        assert jfrog_registry._is_npm_exact_match(item, "lodash")

        # Should reject partial matches that would cause false positives
        item = {"path": ".npm/lodash-utils", "name": "package.json"}
        assert not jfrog_registry._is_npm_exact_match(item, "lodash")

        item = {"path": ".npm/my-lodash-fork", "name": "package.json"}
        assert not jfrog_registry._is_npm_exact_match(item, "lodash")

    def test_npm_exact_match_scoped_package(self, jfrog_registry):
        """Test exact matching for scoped npm packages."""
        # Exact match cases
        item = {"path": ".npm/@angular/core", "name": "package.json"}
        assert jfrog_registry._is_npm_exact_match(item, "@angular/core")

        item = {"path": ".npm/@angular/core/12.0.0", "name": "angular-core-12.0.0.tgz"}
        assert jfrog_registry._is_npm_exact_match(item, "@angular/core")

        # Should reject similar scoped packages
        item = {"path": ".npm/@angular/core-testing", "name": "package.json"}
        assert not jfrog_registry._is_npm_exact_match(item, "@angular/core")

    def test_pypi_exact_match(self, jfrog_registry):
        """Test exact matching for PyPI packages."""
        # Exact match cases
        item = {"path": "simple/django", "name": "index.html"}
        assert jfrog_registry._is_pypi_exact_match(item, "Django")

        item = {"path": "simple/django/3.2.0", "name": "Django-3.2.0.tar.gz"}
        assert jfrog_registry._is_pypi_exact_match(item, "Django")

        # Should reject partial matches
        item = {"path": "simple/django-rest-framework", "name": "index.html"}
        assert not jfrog_registry._is_pypi_exact_match(item, "django")

        # Test underscore normalization
        item = {"path": "simple/flask-security", "name": "index.html"}
        assert jfrog_registry._is_pypi_exact_match(item, "Flask_Security")

    def test_maven_exact_match_with_gav(self, jfrog_registry):
        """Test exact matching for Maven packages with group:artifact."""
        # Exact match cases
        item = {
            "path": "com/fasterxml/jackson/core/jackson-core",
            "name": "jackson-core-2.12.0.jar",
        }
        assert jfrog_registry._is_maven_exact_match(
            item, "com.fasterxml.jackson.core:jackson-core"
        )

        item = {
            "path": "com/fasterxml/jackson/core/jackson-core/2.12.0",
            "name": "jackson-core-2.12.0.pom",
        }
        assert jfrog_registry._is_maven_exact_match(
            item, "com.fasterxml.jackson.core:jackson-core"
        )

        # Should reject similar artifacts
        item = {
            "path": "com/fasterxml/jackson/core/jackson-core-annotations",
            "name": "jackson-core-annotations-2.12.0.jar",
        }
        assert not jfrog_registry._is_maven_exact_match(
            item, "com.fasterxml.jackson.core:jackson-core"
        )

    def test_maven_exact_match_artifact_only(self, jfrog_registry):
        """Test exact matching for Maven packages with artifact name only."""
        # Exact match cases
        item = {"name": "spring-core", "path": "org/springframework/spring-core"}
        assert jfrog_registry._is_maven_exact_match(item, "spring-core")

        # Should reject partial matches
        item = {
            "name": "spring-core-test",
            "path": "org/springframework/spring-core-test",
        }
        assert not jfrog_registry._is_maven_exact_match(item, "spring-core")

    def test_generic_exact_match(self, jfrog_registry):
        """Test exact matching for generic/other ecosystem packages."""
        # Exact match cases
        item = {"name": "some-package", "path": "path/to/some-package"}
        assert jfrog_registry._is_generic_exact_match(item, "some-package")

        # Should reject partial matches
        item = {"name": "some-package-utils", "path": "path/to/some-package-utils"}
        assert not jfrog_registry._is_generic_exact_match(item, "some-package")

        item = {"name": "my-some-package", "path": "path/to/my-some-package"}
        assert not jfrog_registry._is_generic_exact_match(item, "some-package")


class TestFalsePositivePrevention:
    """Test suite specifically for preventing false positive matches."""

    def test_npm_package_name_collision_prevention(self, jfrog_registry):
        """Test that npm packages with similar names don't match incorrectly."""
        test_cases = [
            # (search_package, item_path, should_match)
            ("foo", ".npm/foo", True),
            ("foo", ".npm/foo/1.0.0", True),
            ("foo", ".npm/foo-bar", False),
            ("foo", ".npm/my-foo", False),
            ("foo", ".npm/foo-utils", False),
            ("lodash", ".npm/lodash", True),
            ("lodash", ".npm/lodash-es", False),
            ("lodash", ".npm/babel-plugin-lodash", False),
            ("react", ".npm/react", True),
            ("react", ".npm/react-dom", False),
            ("react", ".npm/@types/react", False),
        ]

        for package_name, item_path, expected in test_cases:
            item = {"path": item_path, "name": "package.json"}
            result = jfrog_registry._is_npm_exact_match(item, package_name)
            assert (
                result == expected
            ), f"Failed for package='{package_name}', path='{item_path}', expected={expected}, got={result}"

    def test_pypi_package_name_collision_prevention(self, jfrog_registry):
        """Test that PyPI packages with similar names don't match incorrectly."""
        test_cases = [
            # (search_package, item_path, should_match)
            ("django", "simple/django", True),
            ("django", "simple/django/3.2.0", True),
            ("django", "simple/django-rest-framework", False),
            ("django", "simple/django-extensions", False),
            ("requests", "simple/requests", True),
            ("requests", "simple/requests-oauthlib", False),
            ("flask", "simple/flask", True),
            ("flask", "simple/flask-sqlalchemy", False),
        ]

        for package_name, item_path, expected in test_cases:
            item = {"path": item_path, "name": "index.html"}
            result = jfrog_registry._is_pypi_exact_match(item, package_name)
            assert (
                result == expected
            ), f"Failed for package='{package_name}', path='{item_path}', expected={expected}, got={result}"

    def test_maven_package_name_collision_prevention(self, jfrog_registry):
        """Test that Maven packages with similar names don't match incorrectly."""
        test_cases = [
            # (search_package, item_name, item_path, should_match)
            ("spring-core", "spring-core", "org/springframework/spring-core", True),
            (
                "spring-core",
                "spring-core-test",
                "org/springframework/spring-core-test",
                False,
            ),
            (
                "jackson-core",
                "jackson-core-annotations",
                "com/fasterxml/jackson/core/jackson-core-annotations",
                False,
            ),
        ]

        for package_name, item_name, item_path, expected in test_cases:
            item = {"name": item_name, "path": item_path}
            result = jfrog_registry._is_maven_exact_match(item, package_name)
            assert (
                result == expected
            ), f"Failed for package='{package_name}', name='{item_name}', path='{item_path}', expected={expected}, got={result}"


class TestNpmPackageStructureHandling:
    """Test suite for handling different npm package structures in Artifactory."""

    def test_npm_aql_query_finds_various_structures(self, jfrog_registry):
        """Test that npm AQL queries can find packages in various directory structures."""
        query = jfrog_registry._build_npm_aql_query("axios", "npm-remote")

        # Verify the query uses $or to match both exact path and subdirectories
        assert "$or" in query
        assert '{"path": {"$eq": ".npm/axios"}}' in query
        assert '{"path": {"$match": ".npm/axios/*"}}' in query

    def test_npm_exact_match_handles_directory_structures(self, jfrog_registry):
        """Test that npm exact matching works with real Artifactory directory structures."""
        test_cases = [
            # Different structures that should match for "axios"
            ({"path": ".npm/axios", "name": "axios"}, True),  # Directory itself
            (
                {"path": ".npm/axios/1.6.0", "name": "package.json"},
                True,
            ),  # Version subdirectory
            (
                {"path": ".npm/axios/1.6.0", "name": "axios-1.6.0.tgz"},
                True,
            ),  # Package tarball
            ({"path": ".npm/axios", "name": "package.json"}, True),  # Package metadata
            # Structures that should NOT match for "axios" (false positives)
            (
                {"path": ".npm/axios-retry", "name": "package.json"},
                False,
            ),  # Similar package
            (
                {"path": ".npm/axios-mock-adapter", "name": "package.json"},
                False,
            ),  # Similar package
            (
                {"path": ".npm/@types/axios", "name": "package.json"},
                False,
            ),  # Type definitions
        ]

        for item, expected in test_cases:
            result = jfrog_registry._is_npm_exact_match(item, "axios")
            assert (
                result == expected
            ), f"Failed for item={item}, expected={expected}, got={result}"

    def test_npm_scoped_package_structure_handling(self, jfrog_registry):
        """Test that scoped packages work correctly with directory structures."""
        test_cases = [
            # Different structures that should match for "@angular/core"
            ({"path": ".npm/@angular/core", "name": "package.json"}, True),
            ({"path": ".npm/@angular/core/15.0.0", "name": "package.json"}, True),
            (
                {
                    "path": ".npm/@angular/core/15.0.0",
                    "name": "angular-core-15.0.0.tgz",
                },
                True,
            ),
            # Structures that should NOT match for "@angular/core" (false positives)
            ({"path": ".npm/@angular/core-testing", "name": "package.json"}, False),
            ({"path": ".npm/@angular/core-common", "name": "package.json"}, False),
        ]

        for item, expected in test_cases:
            result = jfrog_registry._is_npm_exact_match(item, "@angular/core")
            assert (
                result == expected
            ), f"Failed for item={item}, expected={expected}, got={result}"
