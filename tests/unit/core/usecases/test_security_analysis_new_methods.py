"""Tests for new security_analysis methods (wildcard compression and crossref_analysis_with_packages)."""

from unittest.mock import AsyncMock, Mock

import pytest

from src.core.entities.malicious_package import MaliciousPackage
from src.core.entities.registry_package_match import RegistryPackageMatchBuilder
from src.core.usecases.security_analysis import SecurityAnalysisUseCase


class TestSecurityAnalysisNewMethods:
    """Test cases for new SecurityAnalysisUseCase methods."""

    @pytest.fixture
    def mock_packages_feed(self):
        """Mock packages feed for testing."""
        feed = Mock()
        feed.fetch_malicious_packages = AsyncMock(return_value=[])
        feed.get_available_ecosystems = AsyncMock(return_value=["npm", "pypi"])
        return feed

    @pytest.fixture
    def mock_registry_service(self):
        """Mock registry service for testing."""
        service = Mock()
        service.health_check = AsyncMock(return_value=True)
        service.search_packages = AsyncMock(return_value=[])
        service.search_packages_wildcard = AsyncMock(return_value=[])
        service.discover_repositories_by_ecosystem = AsyncMock(
            return_value=["test-repo"]
        )
        service.get_registry_name = Mock(return_value="JFrog")
        service.get_supported_ecosystems = AsyncMock(return_value=["npm", "pypi"])
        service.close = AsyncMock()
        return service

    @pytest.fixture
    def use_case(self, mock_packages_feed, mock_registry_service):
        """Create SecurityAnalysisUseCase instance for testing."""
        return SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)

    @pytest.fixture
    def sample_packages(self):
        """Create sample malicious packages for testing."""
        return [
            MaliciousPackage(
                name="test-package-1",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/test-package-1@1.0.0",
                advisory_id="TEST-001",
                summary="Test package 1",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
            MaliciousPackage(
                name="test-package-2",
                ecosystem="npm",
                version="2.0.0",
                package_url="pkg:npm/test-package-2@2.0.0",
                advisory_id="TEST-002",
                summary="Test package 2",
                details="Details",
                aliases=[],
                affected_versions=["2.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
        ]

    @pytest.mark.asyncio
    async def test_crossref_analysis_with_packages(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test crossref_analysis_with_packages basic functionality."""
        mock_registry_service.health_check.return_value = True
        mock_registry_service.search_packages.return_value = []

        result = await use_case.crossref_analysis_with_packages(
            malicious_packages=sample_packages,
            save_report=False,
            send_notifications=False,
        )

        assert result["success"] is True
        assert result["total_osv_packages"] == 2
        assert "found_matches" in result
        assert "safe_packages" in result
        assert "not_found_count" in result

    @pytest.mark.asyncio
    async def test_crossref_analysis_with_packages_empty_list(
        self, use_case, mock_registry_service
    ):
        """Test crossref_analysis_with_packages with empty package list."""
        result = await use_case.crossref_analysis_with_packages(
            malicious_packages=[],
            save_report=False,
            send_notifications=False,
        )

        assert result["success"] is True
        assert result["total_osv_packages"] == 0
        assert len(result["found_matches"]) == 0

    @pytest.mark.asyncio
    async def test_crossref_analysis_with_packages_with_matches(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test crossref_analysis_with_packages works with mocked results."""
        # Create packages with common prefix to trigger wildcard grouping
        packages_with_prefix = [
            MaliciousPackage(
                name="test-package-1",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/test-package-1@1.0.0",
                advisory_id="TEST-001",
                summary="Test",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
            MaliciousPackage(
                name="test-package-2",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/test-package-2@1.0.0",
                advisory_id="TEST-002",
                summary="Test",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
        ]

        # Mock wildcard search to return matching package
        mock_registry_service.search_packages_wildcard.return_value = [
            {
                "name": "test-package-1",
                "version": "1.0.0",
                "repo": "npm-local",
                "path": "test-package-1-1.0.0.tgz",
            }
        ]

        result = await use_case.crossref_analysis_with_packages(
            malicious_packages=packages_with_prefix,
            save_report=False,
            send_notifications=False,
        )

        assert result["success"] is True
        # At minimum the method completes successfully
        assert "found_matches" in result

    @pytest.mark.asyncio
    async def test_check_packages_with_wildcard_compression(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test _check_packages_with_wildcard_compression method."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        # Mock wildcard search to return results
        mock_registry_service.search_packages_wildcard.return_value = [
            {
                "name": "test-package-1",
                "version": "1.0.0",
                "repo": "npm-local",
                "path": "test-package-1-1.0.0.tgz",
            }
        ]

        results = await use_case._check_packages_with_wildcard_compression(
            malicious_packages=sample_packages,
            match_builder=match_builder,
            max_concurrent=5,
        )

        assert isinstance(results, list)
        # Results should contain match information
        for result in results:
            assert "type" in result
            assert "data" in result
            assert "package" in result["data"]
            assert isinstance(result["data"]["package"], MaliciousPackage)

    @pytest.mark.asyncio
    async def test_check_packages_with_wildcard_compression_no_matches(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test wildcard compression when no matches found."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        # Mock wildcard search to return empty results
        mock_registry_service.search_packages_wildcard.return_value = []

        results = await use_case._check_packages_with_wildcard_compression(
            malicious_packages=sample_packages,
            match_builder=match_builder,
            max_concurrent=5,
        )

        assert isinstance(results, list)
        assert len(results) == len(sample_packages)
        # All packages should be "not found"
        for result in results:
            assert result["type"] == "not_found"

    @pytest.mark.asyncio
    async def test_check_packages_with_wildcard_compression_error_handling(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test error handling in wildcard compression."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        # Mock wildcard search to raise exception
        mock_registry_service.search_packages_wildcard.side_effect = Exception(
            "Network error"
        )

        results = await use_case._check_packages_with_wildcard_compression(
            malicious_packages=sample_packages,
            match_builder=match_builder,
            max_concurrent=5,
        )

        # Should handle errors gracefully
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_process_package_result_match_found(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test _process_package_result when match is found."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        registry_results = [
            {
                "name": "test-package-1",
                "version": "1.0.0",
                "repo": "npm-local",
                "path": "test-package-1-1.0.0.tgz",
            }
        ]

        result = await use_case._process_package_result(
            malicious_pkg=sample_packages[0],
            registry_results=registry_results,
            match_builder=match_builder,
            ecosystem="npm",
        )

        assert result["type"] == "match"
        assert result["data"]["package"] == sample_packages[0]

    @pytest.mark.asyncio
    async def test_process_package_result_safe(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test _process_package_result when package is safe (different version)."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        registry_results = [
            {
                "name": "test-package-1",
                "version": "2.0.0",  # Different version
                "repo": "npm-local",
                "path": "test-package-1-2.0.0.tgz",
            }
        ]

        result = await use_case._process_package_result(
            malicious_pkg=sample_packages[0],
            registry_results=registry_results,
            match_builder=match_builder,
            ecosystem="npm",
        )

        assert result["type"] == "safe"
        assert result["data"]["package"] == sample_packages[0]

    @pytest.mark.asyncio
    async def test_process_package_result_not_found(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test _process_package_result when package not found."""
        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        registry_results = []

        result = await use_case._process_package_result(
            malicious_pkg=sample_packages[0],
            registry_results=registry_results,
            match_builder=match_builder,
            ecosystem="npm",
        )

        assert result["type"] == "not_found"
        assert result["data"]["package"] == sample_packages[0]

    @pytest.mark.asyncio
    async def test_wildcard_compression_integration(
        self, use_case, mock_registry_service
    ):
        """Test wildcard compression with packages that should be grouped."""
        # Create packages with common prefix
        packages = [
            MaliciousPackage(
                name="lodash-utils",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/lodash-utils@1.0.0",
                advisory_id="TEST-001",
                summary="Test",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
            MaliciousPackage(
                name="lodash-core",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/lodash-core@1.0.0",
                advisory_id="TEST-002",
                summary="Test",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
            MaliciousPackage(
                name="lodash-helpers",
                ecosystem="npm",
                version="1.0.0",
                package_url="pkg:npm/lodash-helpers@1.0.0",
                advisory_id="TEST-003",
                summary="Test",
                details="Details",
                aliases=[],
                affected_versions=["1.0.0"],
                database_specific={},
                published_at=None,
                modified_at=None,
            ),
        ]

        match_builder = RegistryPackageMatchBuilder(registry_name="JFrog")

        # Mock wildcard search to be called once for "lodash*"
        mock_registry_service.search_packages_wildcard.return_value = [
            {
                "name": "lodash-utils",
                "version": "1.0.0",
                "repo": "npm-local",
                "path": "lodash-utils-1.0.0.tgz",
            }
        ]

        results = await use_case._check_packages_with_wildcard_compression(
            malicious_packages=packages,
            match_builder=match_builder,
            max_concurrent=5,
        )

        assert isinstance(results, list)
        assert len(results) == 3

        # Verify wildcard search was called (should group lodash packages)
        assert mock_registry_service.search_packages_wildcard.called

    @pytest.mark.asyncio
    async def test_crossref_with_packages_progress_callback(
        self, use_case, sample_packages, mock_registry_service
    ):
        """Test that progress callback is called during analysis."""
        progress_calls = []

        def progress_callback(current, total, message):
            progress_calls.append(
                {"current": current, "total": total, "message": message}
            )

        mock_registry_service.search_packages.return_value = []

        await use_case.crossref_analysis_with_packages(
            malicious_packages=sample_packages,
            save_report=False,
            send_notifications=False,
            progress_callback=progress_callback,
        )

        # Progress callback should have been called
        assert len(progress_calls) > 0
