"""
Unit tests for JFrog registry version extraction functionality.
Tests the actual _extract_version_from_filename method instead of duplicating regex patterns.
"""

import pytest

from src.providers.registries.jfrog_registry import JFrogRegistry


@pytest.fixture
def jfrog_registry():
    """Create a JFrogRegistry instance for testing."""
    # Initialize with minimal required config for testing
    return JFrogRegistry(
        base_url="https://test.jfrog.io", username="test", password="test"
    )


class TestJFrogVersionExtraction:
    """Tests for JFrog registry version extraction method."""

    def test_exact_package_name_version_extraction(self, jfrog_registry):
        """Test version extraction for exact package name matches."""
        # Should extract version from exact package name matches
        version = jfrog_registry._extract_version_from_filename(
            "test-package-1.0.0.json", "test-package", "npm"
        )
        assert version == "1.0.0"

        # Different package names should not match with exact pattern
        # but should fall back to other patterns
        version = jfrog_registry._extract_version_from_filename(
            "other-package-1.0.0.json", "test-package", "npm"
        )
        assert version == "1.0.0"  # Should still extract via fallback patterns

    def test_compound_package_name_version_extraction(self, jfrog_registry):
        """Test version extraction for compound package names containing the search term."""
        # Should extract version from compound package names
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
        # The method should handle cases where .json might remain in version
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

    def test_compound_plugin_package_scenario(self, jfrog_registry):
        """Test compound plugin package name version extraction."""
        version = jfrog_registry._extract_version_from_filename(
            "test-package-webpack-plugin-2.4.0.json", "test-package", "npm"
        )
        assert version == "2.4.0"

    def test_common_package_scenarios(self, jfrog_registry):
        """Test common package version extraction scenarios."""
        test_cases = [
            ("test-package-21.5.0.json", "test-package", "21.5.0"),
            ("test-package-20.9.0.json", "test-package", "20.9.0"),
            ("@test/workspace-21.5.0.json", "@test/workspace", "21.5.0"),
            ("@test/eslint-21.5.0.json", "@test/eslint", "21.5.0"),
        ]

        for filename, package_name, expected_version in test_cases:
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
