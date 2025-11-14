"""Unit tests for WildcardCompressor."""

from datetime import datetime, timezone

from src.core.entities import MaliciousPackage
from src.core.wildcard_compressor import WildcardCompressor


class TestWildcardCompressor:
    """Test suite for WildcardCompressor class."""

    def test_compress_packages_with_scoped_npm(self):
        """Test compression of scoped npm packages (@org/package)."""
        packages = [
            MaliciousPackage(
                name="@walletify/ui",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/@walletify/ui@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="@walletify/core",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/@walletify/core@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="@walletify/utils",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/@walletify/utils@1.0.0",
                advisory_id="TEST-003",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        # Should create one wildcard group for @walletify/*
        assert len(wildcard_groups) == 1
        assert wildcard_groups[0][0] == "@walletify/*"
        assert len(wildcard_groups[0][1]) == 3
        assert len(standalone) == 0

        # Check stats
        stats = compressor.get_compression_stats()
        assert stats["overall"]["total_packages"] == 3
        assert stats["overall"]["wildcard_groups"] == 1
        assert stats["overall"]["queries_compressed"] == 1
        assert stats["overall"]["compression_ratio"] == 3.0

    def test_compress_packages_with_standard_names(self):
        """Test compression of standard package names with common prefixes."""
        packages = [
            MaliciousPackage(
                name="lodash-utils",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-utils@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="lodash-core",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-core@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="lodash-helpers",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-helpers@1.0.0",
                advisory_id="TEST-003",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        # Should create one wildcard group for lodash*
        assert len(wildcard_groups) == 1
        assert wildcard_groups[0][0] == "lodash*"
        assert len(wildcard_groups[0][1]) == 3
        assert len(standalone) == 0

    def test_word_based_prefix_extraction(self):
        """Test that _get_prefix correctly extracts word-based prefixes."""
        compressor = WildcardCompressor()

        # Test scoped packages
        assert compressor._get_prefix("@walletify/ui") == "@walletify/"
        assert compressor._get_prefix("@scope/name") == "@scope/"

        # Test long first word (>= 3 chars)
        assert compressor._get_prefix("lodash-utils") == "lodash"
        assert compressor._get_prefix("express-middleware") == "express"
        assert compressor._get_prefix("webpack-plugin") == "webpack"

        # Test short first word (< 3 chars) - use first 2 words
        assert compressor._get_prefix("my-cool-package") == "my-cool"
        assert compressor._get_prefix("is-number") == "is-number"

        # Test single word
        assert compressor._get_prefix("lodash") == "lodash"
        assert compressor._get_prefix("axios") == "axios"

        # Test with underscores and dots (they get converted to dashes)
        assert compressor._get_prefix("some_package_name") == "some"
        assert (
            compressor._get_prefix("my.package.name") == "my-package"
        )  # "my" is <3 chars, so uses first 2 words

    def test_min_group_size_threshold(self):
        """Test that groups below min_group_size are not created."""
        packages = [
            MaliciousPackage(
                name="lodash-utils",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-utils@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="axios-retry",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/axios-retry@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        # With min_group_size=2, no groups should form (only 1 package per prefix)
        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        assert len(wildcard_groups) == 0
        assert len(standalone) == 2

        # With min_group_size=1, groups should form
        compressor = WildcardCompressor(min_group_size=1)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        assert len(wildcard_groups) == 2
        assert len(standalone) == 0

    def test_compression_statistics(self):
        """Test that compression statistics are calculated correctly."""
        packages = [
            MaliciousPackage(
                name="test-package-1",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/test-package-1@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="test-package-2",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/test-package-2@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="test-package-3",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/test-package-3@1.0.0",
                advisory_id="TEST-003",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        stats = compressor.get_compression_stats()

        assert "overall" in stats
        assert stats["overall"]["total_packages"] == 3
        assert stats["overall"]["wildcard_groups"] == 1
        assert stats["overall"]["standalone_packages"] == 0
        assert stats["overall"]["queries_original"] == 3
        assert stats["overall"]["queries_compressed"] == 1
        assert stats["overall"]["compression_ratio"] == 3.0
        assert stats["overall"]["reduction_percentage"] > 60

        # Check ecosystem-specific stats
        assert "npm" in stats
        assert stats["npm"]["total_packages"] == 3
        assert stats["npm"]["wildcard_groups"] == 1

    def test_empty_package_list(self):
        """Test compression with empty package list."""
        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages([])

        assert len(wildcard_groups) == 0
        assert len(standalone) == 0

        stats = compressor.get_compression_stats()
        assert stats["overall"]["total_packages"] == 0

    def test_multiple_ecosystems(self):
        """Test compression across multiple ecosystems."""
        packages = [
            MaliciousPackage(
                name="lodash-utils",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-utils@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="lodash-core",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-core@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="requests-utils",
                version="1.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/requests-utils@1.0.0",
                advisory_id="TEST-003",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="requests-core",
                version="1.0.0",
                ecosystem="PyPI",
                package_url="pkg:pypi/requests-core@1.0.0",
                advisory_id="TEST-004",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        # Should create 2 groups (one per ecosystem)
        assert len(wildcard_groups) == 2
        assert len(standalone) == 0

        # Check stats per ecosystem
        stats = compressor.get_compression_stats()
        assert "npm" in stats
        assert "PyPI" in stats
        assert stats["npm"]["wildcard_groups"] == 1
        assert stats["PyPI"]["wildcard_groups"] == 1
        assert stats["overall"]["total_packages"] == 4
        assert stats["overall"]["queries_compressed"] == 2

    def test_mixed_groupable_and_standalone(self):
        """Test with mix of groupable and standalone packages."""
        packages = [
            # Group 1: lodash packages (will group)
            MaliciousPackage(
                name="lodash-utils",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-utils@1.0.0",
                advisory_id="TEST-001",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            MaliciousPackage(
                name="lodash-core",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/lodash-core@1.0.0",
                advisory_id="TEST-002",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
            # Standalone: single unique package
            MaliciousPackage(
                name="axios",
                version="1.0.0",
                ecosystem="npm",
                package_url="pkg:npm/axios@1.0.0",
                advisory_id="TEST-003",
                summary="Test package",
                details="Test details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=datetime.now(timezone.utc),
                modified_at=datetime.now(timezone.utc),
            ),
        ]

        compressor = WildcardCompressor(min_group_size=2)
        wildcard_groups, standalone = compressor.compress_packages(packages)

        # Should create 1 group + 1 standalone
        assert len(wildcard_groups) == 1
        assert wildcard_groups[0][0] == "lodash*"
        assert len(wildcard_groups[0][1]) == 2
        assert len(standalone) == 1
        assert standalone[0].name == "axios"

        stats = compressor.get_compression_stats()
        assert stats["overall"]["wildcard_groups"] == 1
        assert stats["overall"]["standalone_packages"] == 1
        assert stats["overall"]["queries_compressed"] == 2  # 1 group + 1 standalone
