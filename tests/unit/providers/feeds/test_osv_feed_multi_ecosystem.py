"""Unit tests for OSV feed multi-ecosystem support."""

from unittest.mock import patch

import pytest

from src.core.entities import MaliciousPackage
from src.providers.exceptions import FeedError
from src.providers.feeds.osv_feed import OSVFeed


class TestOSVFeedMultiEcosystem:
    """Test OSV feed multi-ecosystem functionality."""

    @pytest.fixture
    def osv_feed(self):
        """Create OSV feed instance."""
        return OSVFeed()

    @pytest.mark.asyncio
    async def test_get_available_ecosystems_success(self, osv_feed):
        """Test successful ecosystem discovery."""

        # Mock the _get_malicious_package_ids method to return data for some ecosystems
        async def mock_get_malicious_package_ids(ecosystem, hours):
            if ecosystem in ["npm", "PyPI", "Maven"]:
                return ["MAL-001", "MAL-002"]  # Return some malicious IDs
            else:
                return []  # No malicious packages for other ecosystems

        with patch.object(
            osv_feed,
            "_get_malicious_package_ids",
            side_effect=mock_get_malicious_package_ids,
        ):
            ecosystems = await osv_feed.get_available_ecosystems()

            assert set(ecosystems) == {"npm", "PyPI", "Maven"}

    @pytest.mark.asyncio
    async def test_get_available_ecosystems_empty(self, osv_feed):
        """Test ecosystem discovery with no valid ecosystems."""

        # Mock _get_malicious_package_ids to return empty list for all ecosystems
        async def mock_get_malicious_package_ids(ecosystem, hours):
            return []  # No malicious packages for any ecosystem

        with patch.object(
            osv_feed,
            "_get_malicious_package_ids",
            side_effect=mock_get_malicious_package_ids,
        ):
            ecosystems = await osv_feed.get_available_ecosystems()

            assert ecosystems == []

    @pytest.mark.asyncio
    async def test_get_available_ecosystems_error(self, osv_feed):
        """Test ecosystem discovery with storage error."""
        with patch.object(
            osv_feed,
            "_get_malicious_package_ids",
            side_effect=Exception("Storage error"),
        ):
            ecosystems = await osv_feed.get_available_ecosystems()

            # Should return empty list on error, not raise exception
            assert ecosystems == []

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_all_ecosystems(self, osv_feed):
        """Test fetching packages from all available ecosystems."""
        # Create mock packages with all required fields
        mock_npm_package = MaliciousPackage(
            name="malicious-npm",
            ecosystem="npm",
            version="1.0.0",
            package_url="pkg:npm/malicious-npm@1.0.0",
            advisory_id="MAL-001",
            summary="Malicious npm package",
            details="Test details",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None,
        )

        mock_pypi_package = MaliciousPackage(
            name="malicious-pypi",
            ecosystem="PyPI",
            version="2.0.0",
            package_url="pkg:pypi/malicious-pypi@2.0.0",
            advisory_id="MAL-002",
            summary="Malicious PyPI package",
            details="Test details",
            aliases=[],
            affected_versions=["2.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None,
        )

        with patch.object(
            osv_feed, "get_available_ecosystems", return_value=["npm", "PyPI"]
        ) as mock_get_ecosystems:
            with patch.object(
                osv_feed, "_fetch_malicious_packages_for_ecosystem"
            ) as mock_fetch_ecosystem:

                def mock_fetch_side_effect(ecosystem, max_packages, hours):
                    if ecosystem == "npm":
                        return [mock_npm_package]
                    elif ecosystem == "PyPI":
                        return [mock_pypi_package]
                    return []

                mock_fetch_ecosystem.side_effect = mock_fetch_side_effect

                # Test with no specific ecosystems (should fetch all)
                packages = await osv_feed.fetch_malicious_packages(
                    max_packages=100, hours=24
                )

                assert len(packages) == 2
                assert packages[0].ecosystem == "npm"
                assert packages[1].ecosystem == "PyPI"

                # Verify ecosystem discovery was called
                mock_get_ecosystems.assert_called_once()

                # Verify ecosystem-specific fetching was called for each ecosystem
                assert mock_fetch_ecosystem.call_count == 2

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_specific_ecosystems(self, osv_feed):
        """Test fetching packages from specific ecosystems."""
        mock_package = MaliciousPackage(
            name="test-package",
            ecosystem="npm",
            version="1.0.0",
            package_url="pkg:npm/test-package@1.0.0",
            advisory_id="MAL-001",
            summary="Test package",
            details="Test details",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None,
        )

        with patch.object(
            osv_feed,
            "_fetch_malicious_packages_for_ecosystem",
            return_value=[mock_package],
        ) as mock_fetch:
            # Test with specific ecosystems
            packages = await osv_feed.fetch_malicious_packages(
                max_packages=100, hours=24, ecosystems=["npm"]
            )

            assert len(packages) == 1
            assert packages[0].ecosystem == "npm"

            # Should only call fetch for specified ecosystem
            mock_fetch.assert_called_once_with("npm", 100, 24)

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_ecosystem_failure(self, osv_feed):
        """Test handling of ecosystem-specific failures."""
        mock_package = MaliciousPackage(
            name="fail-package",
            ecosystem="PyPI",
            version="1.0.0",
            package_url="pkg:pypi/fail-package@1.0.0",
            advisory_id="MAL-002",
            summary="Failing package",
            details="Test details",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None,
        )

        with patch.object(
            osv_feed, "get_available_ecosystems", return_value=["npm", "PyPI"]
        ):
            with patch.object(
                osv_feed, "_fetch_malicious_packages_for_ecosystem"
            ) as mock_fetch:

                def mock_fetch_side_effect(ecosystem, max_packages, hours):
                    if ecosystem == "npm":
                        raise FeedError("npm fetch failed")
                    elif ecosystem == "PyPI":
                        return [mock_package]
                    return []

                mock_fetch.side_effect = mock_fetch_side_effect

                # Should continue with other ecosystems despite one failure
                packages = await osv_feed.fetch_malicious_packages(
                    max_packages=100, hours=24
                )

                assert len(packages) == 1
                assert packages[0].ecosystem == "PyPI"

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_empty_ecosystems(self, osv_feed):
        """Test with empty ecosystems list."""
        with patch.object(
            osv_feed, "_fetch_malicious_packages_for_ecosystem"
        ) as mock_fetch:
            packages = await osv_feed.fetch_malicious_packages(
                max_packages=100, hours=24, ecosystems=[]
            )

            assert packages == []
            mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_no_packages_found(self, osv_feed):
        """Test when no packages are found in any ecosystem."""
        with patch.object(
            osv_feed, "get_available_ecosystems", return_value=["npm", "PyPI"]
        ):
            with patch.object(
                osv_feed, "_fetch_malicious_packages_for_ecosystem", return_value=[]
            ):
                packages = await osv_feed.fetch_malicious_packages(
                    max_packages=100, hours=24
                )

                assert packages == []

    @pytest.mark.asyncio
    async def test_backward_compatibility_single_ecosystem(self, osv_feed):
        """Test backward compatibility with existing single ecosystem usage."""
        mock_package = MaliciousPackage(
            name="compat-package",
            ecosystem="npm",
            version="1.0.0",
            package_url="pkg:npm/compat-package@1.0.0",
            advisory_id="MAL-003",
            summary="Compatibility test package",
            details="Test details",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=None,
            modified_at=None,
        )

        with patch.object(osv_feed, "get_available_ecosystems", return_value=["npm"]):
            with patch.object(
                osv_feed,
                "_fetch_malicious_packages_for_ecosystem",
                return_value=[mock_package],
            ):
                # Old-style call should still work
                packages = await osv_feed.fetch_malicious_packages(
                    max_packages=50, hours=12
                )

                # Should get packages from discovered ecosystems
                assert len(packages) == 1
                assert packages[0].ecosystem == "npm"
