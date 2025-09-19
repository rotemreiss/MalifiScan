"""Tests for security_analysis use case."""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.core.entities.malicious_package import MaliciousPackage


class TestSecurityAnalysisUseCase:
    """Test cases for SecurityAnalysisUseCase."""

    @pytest.fixture
    def mock_packages_feed(self):
        """Mock packages feed for testing."""
        feed = Mock()
        feed.fetch_malicious_packages = AsyncMock(return_value=[])
        return feed

    @pytest.fixture
    def mock_registry_service(self):
        """Mock registry service for testing."""
        service = Mock()
        service.health_check = AsyncMock(return_value=True)
        service.search_packages = AsyncMock(return_value=[])
        service.close = AsyncMock()
        return service

    @pytest.fixture
    def mock_logger(self):
        """Mock logger for testing."""
        with patch('src.core.usecases.security_analysis.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            yield mock_logger

    @pytest.fixture
    def use_case(self, mock_packages_feed, mock_registry_service):
        """Create SecurityAnalysisUseCase instance for testing."""
        return SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)

    @pytest.fixture
    def sample_malicious_package(self):
        """Create a sample malicious package for testing."""
        return MaliciousPackage(
            name="malicious-package",
            ecosystem="npm",
            version="1.0.0",
            package_url="pkg:npm/malicious-package@1.0.0",
            advisory_id="OSV-2023-001",
            summary="Malicious package summary",
            details="Detailed description",
            aliases=["CVE-2023-001"],
            affected_versions=["1.0.0", "1.0.1"],
            database_specific={},
            published_at=None,
            modified_at=None
        )

    def test_init(self, mock_packages_feed, mock_registry_service, mock_logger):
        """Test initialization of SecurityAnalysisUseCase."""
        use_case = SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)
        
        assert use_case.packages_feed == mock_packages_feed
        assert use_case.registry_service == mock_registry_service
        assert use_case.logger is not None

    @pytest.mark.asyncio
    async def test_crossref_analysis_no_malicious_packages(self, use_case, mock_packages_feed, mock_logger):
        """Test crossref_analysis when no malicious packages are found."""
        hours = 6
        ecosystem = "npm"
        
        result = await use_case.crossref_analysis(hours, ecosystem)
        
        assert result["success"] is True
        assert result["total_osv_packages"] == 0
        assert result["filtered_packages"] == 0
        assert result["found_matches"] == []
        assert result["safe_packages"] == []
        assert result["errors"] == []
        assert result["not_found_count"] == 0
        
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=None, hours=hours
        )

    @pytest.mark.asyncio
    async def test_crossref_analysis_default_parameters(self, use_case, mock_packages_feed, mock_logger):
        """Test crossref_analysis with default parameters."""
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=None, hours=6
        )

    @pytest.mark.asyncio
    async def test_crossref_analysis_custom_parameters(self, use_case, mock_packages_feed, mock_logger):
        """Test crossref_analysis with custom parameters."""
        hours = 12
        ecosystem = "pypi"
        limit = 100
        
        result = await use_case.crossref_analysis(hours, ecosystem, limit)
        
        mock_packages_feed.fetch_malicious_packages.assert_called_once_with(
            max_packages=limit, hours=hours
        )

    @pytest.mark.asyncio
    async def test_crossref_analysis_ecosystem_filtering(self, use_case, mock_packages_feed, mock_logger):
        """Test that packages are filtered by ecosystem."""
        npm_package = MaliciousPackage(
            name="npm-package", ecosystem="npm", version="1.0.0", package_url="pkg:npm/npm-package@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=[], database_specific={},
            published_at=None, modified_at=None
        )
        pypi_package = MaliciousPackage(
            name="pypi-package", ecosystem="pypi", version="1.0.0", package_url="pkg:pypi/pypi-package@1.0.0",
            advisory_id="OSV-002", summary="", details="", aliases=[], affected_versions=[], database_specific={},
            published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [npm_package, pypi_package]
        
        result = await use_case.crossref_analysis(ecosystem="npm")
        
        # Should only process npm packages
        assert result["filtered_packages"] == 1

    @pytest.mark.asyncio
    async def test_crossref_analysis_case_insensitive_ecosystem_filtering(self, use_case, mock_packages_feed, mock_logger):
        """Test that ecosystem filtering is case insensitive."""
        npm_package = MaliciousPackage(
            name="npm-package", ecosystem="NPM", version="1.0.0", package_url="pkg:npm/npm-package@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=[], database_specific={},
            published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [npm_package]
        
        result = await use_case.crossref_analysis(ecosystem="npm")
        
        assert result["filtered_packages"] == 1

    @pytest.mark.asyncio
    async def test_crossref_analysis_registry_unhealthy(self, use_case, mock_packages_feed, mock_registry_service, sample_malicious_package, mock_logger):
        """Test crossref_analysis when registry is unhealthy."""
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_registry_service.health_check.return_value = False
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is False
        assert result["error"] == "JFrog registry is not accessible"
        assert result["total_osv_packages"] == 1
        assert result["filtered_packages"] == 1
        
        mock_registry_service.search_packages.assert_not_called()

    @pytest.mark.asyncio
    async def test_crossref_analysis_package_not_found_in_registry(self, use_case, mock_packages_feed, mock_registry_service, sample_malicious_package, mock_logger):
        """Test crossref_analysis when package is not found in registry."""
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_registry_service.search_packages.return_value = []  # Not found
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert result["not_found_count"] == 1
        assert len(result["found_matches"]) == 0
        assert len(result["safe_packages"]) == 0

    @pytest.mark.asyncio
    async def test_crossref_analysis_version_match_found(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis when a version match is found."""
        malicious_package = MaliciousPackage(
            name="malicious-package", ecosystem="npm", version="1.0.0", package_url="pkg:npm/malicious-package@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=["1.0.0", "1.0.1"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "malicious-package", "version": "1.0.0"},
            {"name": "malicious-package", "version": "2.0.0"}
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["found_matches"]) == 1
        assert len(result["safe_packages"]) == 0
        assert result["not_found_count"] == 0
        
        match = result["found_matches"][0]
        assert match["package"] == malicious_package
        assert match["matching_versions"] == ["1.0.0"]
        assert match["all_jfrog_versions"] == ["1.0.0", "2.0.0"]
        assert match["malicious_versions"] == ["1.0.0", "1.0.1"]

    @pytest.mark.asyncio
    async def test_crossref_analysis_no_version_match(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis when package is found but no version matches."""
        malicious_package = MaliciousPackage(
            name="package-name", ecosystem="npm", version="1.0.0", package_url="pkg:npm/package-name@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=["1.0.0", "1.0.1"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "package-name", "version": "2.0.0"},
            {"name": "package-name", "version": "3.0.0"}
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["found_matches"]) == 0
        assert len(result["safe_packages"]) == 1
        assert result["not_found_count"] == 0
        
        safe_package = result["safe_packages"][0]
        assert safe_package["package"] == malicious_package
        assert safe_package["jfrog_versions"] == ["2.0.0", "3.0.0"]
        assert safe_package["malicious_versions"] == ["1.0.0", "1.0.1"]

    @pytest.mark.asyncio
    async def test_crossref_analysis_multiple_version_matches(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis when multiple versions match."""
        malicious_package = MaliciousPackage(
            name="multi-match", ecosystem="npm", version="1.0.0", package_url="pkg:npm/multi-match@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=["1.0.0", "1.1.0", "2.0.0"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "multi-match", "version": "1.0.0"},
            {"name": "multi-match", "version": "1.1.0"},
            {"name": "multi-match", "version": "1.5.0"},
            {"name": "multi-match", "version": "2.0.0"}
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["found_matches"]) == 1
        
        match = result["found_matches"][0]
        assert set(match["matching_versions"]) == {"1.0.0", "1.1.0", "2.0.0"}

    @pytest.mark.asyncio
    async def test_crossref_analysis_package_without_affected_versions(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis with package that has no affected_versions but has version."""
        malicious_package = MaliciousPackage(
            name="single-version", ecosystem="npm", version="1.0.0", package_url="pkg:npm/single-version@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=[],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "single-version", "version": "1.0.0"}
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        # When affected_versions is empty list, it falls back to [version] if version exists
        # But the implementation checks affected_versions first, and if it exists (even empty), it uses it
        # So empty affected_versions means no versions to match against
        assert len(result["safe_packages"]) == 1
        
        safe_package = result["safe_packages"][0]
        assert safe_package["malicious_versions"] == []  # Empty affected_versions used

    @pytest.mark.asyncio
    async def test_crossref_analysis_package_with_no_version_info(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis with package that has no version information."""
        malicious_package = MaliciousPackage(
            name="no-version", ecosystem="npm", version=None, package_url="pkg:npm/no-version",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=[],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "no-version", "version": "1.0.0"}
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["safe_packages"]) == 1  # No version to match
        
        safe_package = result["safe_packages"][0]
        assert safe_package["malicious_versions"] == []

    @pytest.mark.asyncio
    async def test_crossref_analysis_registry_results_without_version(self, use_case, mock_packages_feed, mock_registry_service, sample_malicious_package, mock_logger):
        """Test crossref_analysis when registry results don't have version field."""
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_registry_service.search_packages.return_value = [
            {"name": "malicious-package"},  # No version field
            {"name": "malicious-package", "version": None}  # Null version
        ]
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["safe_packages"]) == 1  # No versions to match
        
        safe_package = result["safe_packages"][0]
        assert safe_package["jfrog_versions"] == []  # Empty because no valid versions

    @pytest.mark.asyncio
    async def test_crossref_analysis_search_exception(self, use_case, mock_packages_feed, mock_registry_service, sample_malicious_package, mock_logger):
        """Test crossref_analysis when search_packages raises an exception."""
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_registry_service.search_packages.side_effect = Exception("Search failed")
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert len(result["errors"]) == 1
        assert result["errors"][0]["package"] == "malicious-package"
        assert result["errors"][0]["error"] == "Search failed"
        
        mock_registry_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_crossref_analysis_multiple_packages_mixed_results(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis with multiple packages having different outcomes."""
        # Package 1: Found with version match
        package1 = MaliciousPackage(
            name="match-pkg", ecosystem="npm", version="1.0.0", package_url="pkg:npm/match-pkg@1.0.0",
            advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=["1.0.0"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        # Package 2: Found but no version match
        package2 = MaliciousPackage(
            name="safe-pkg", ecosystem="npm", version="1.0.0", package_url="pkg:npm/safe-pkg@1.0.0",
            advisory_id="OSV-002", summary="", details="", aliases=[], affected_versions=["1.0.0"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        # Package 3: Not found
        package3 = MaliciousPackage(
            name="not-found-pkg", ecosystem="npm", version="1.0.0", package_url="pkg:npm/not-found-pkg@1.0.0",
            advisory_id="OSV-003", summary="", details="", aliases=[], affected_versions=["1.0.0"],
            database_specific={}, published_at=None, modified_at=None
        )
        
        mock_packages_feed.fetch_malicious_packages.return_value = [package1, package2, package3]
        
        def mock_search(name, ecosystem):
            if name == "match-pkg":
                return [{"name": "match-pkg", "version": "1.0.0"}]
            elif name == "safe-pkg":
                return [{"name": "safe-pkg", "version": "2.0.0"}]
            else:  # not-found-pkg
                return []
        
        mock_registry_service.search_packages.side_effect = mock_search
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is True
        assert result["total_osv_packages"] == 3
        assert result["filtered_packages"] == 3
        assert len(result["found_matches"]) == 1
        assert len(result["safe_packages"]) == 1
        assert result["not_found_count"] == 1
        assert len(result["errors"]) == 0

    @pytest.mark.asyncio
    async def test_crossref_analysis_main_exception(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test crossref_analysis when main process fails with exception."""
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed failed")
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is False
        assert result["error"] == "Feed failed"
        assert result["total_osv_packages"] == 0
        assert result["filtered_packages"] == 0
        
        # Should still try to cleanup
        mock_registry_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_crossref_analysis_cleanup_exception_ignored(self, use_case, mock_packages_feed, mock_registry_service, mock_logger):
        """Test that cleanup exceptions are ignored during error handling."""
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed failed")
        mock_registry_service.close.side_effect = Exception("Cleanup failed")
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is False
        assert result["error"] == "Feed failed"  # Original error, not cleanup error

    @pytest.mark.asyncio
    async def test_crossref_analysis_registry_service_none_during_cleanup(self, use_case, mock_packages_feed, mock_logger):
        """Test crossref_analysis when registry_service becomes None during error handling."""
        mock_packages_feed.fetch_malicious_packages.side_effect = Exception("Feed failed")
        use_case.registry_service = None
        
        result = await use_case.crossref_analysis()
        
        assert result["success"] is False
        assert result["error"] == "Feed failed"
        # Should not raise an exception during cleanup

    @pytest.mark.asyncio
    async def test_crossref_analysis_logging_calls(self, mock_packages_feed, mock_registry_service):
        """Test that appropriate logging calls are made."""
        with patch('src.core.usecases.security_analysis.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            use_case = SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)
            
            # Test with no packages
            await use_case.crossref_analysis(hours=12, ecosystem="pypi")
            
            # Check that the log message starts with the expected text
            info_calls = mock_logger.info.call_args_list
            assert any(
                call[0][0].startswith("Starting security cross-reference analysis for pypi packages from last 12 hours")
                for call in info_calls
            ), f"Expected log message not found in calls: {[call[0][0] for call in info_calls]}"
            mock_logger.info.assert_any_call("No malicious pypi packages found in the last 12 hours")

    @pytest.mark.asyncio
    async def test_crossref_analysis_logging_with_results(self, mock_packages_feed, mock_registry_service, sample_malicious_package):
        """Test logging calls when packages are found and processed."""
        with patch('src.core.usecases.security_analysis.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            use_case = SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)
            
            mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
            mock_registry_service.search_packages.return_value = []  # Not found
            
            await use_case.crossref_analysis()
            
            mock_logger.info.assert_any_call("Found 1 malicious npm packages to check")
            mock_logger.info.assert_any_call("Cross-reference analysis complete: 0 critical matches, 0 safe packages, 1 not found, 0 errors")

    @pytest.mark.asyncio
    async def test_crossref_analysis_warning_on_critical_match(self, mock_packages_feed, mock_registry_service):
        """Test that warning is logged for critical matches."""
        with patch('src.core.usecases.security_analysis.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            use_case = SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)
            
            malicious_package = MaliciousPackage(
                name="critical-pkg", ecosystem="npm", version="1.0.0", package_url="pkg:npm/critical-pkg@1.0.0",
                advisory_id="OSV-001", summary="", details="", aliases=[], affected_versions=["1.0.0"],
                database_specific={}, published_at=None, modified_at=None
            )
            
            mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]
            mock_registry_service.search_packages.return_value = [{"name": "critical-pkg", "version": "1.0.0"}]
            
            await use_case.crossref_analysis()
            
            mock_logger.warning.assert_any_call("Critical match found: critical-pkg versions ['1.0.0']")

    @pytest.mark.asyncio
    async def test_crossref_analysis_error_logging_for_package_exception(self, mock_packages_feed, mock_registry_service, sample_malicious_package):
        """Test error logging when individual package processing fails."""
        with patch('src.core.usecases.security_analysis.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            use_case = SecurityAnalysisUseCase(mock_packages_feed, mock_registry_service)
            
            mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
            mock_registry_service.search_packages.side_effect = Exception("Search error")
            
            await use_case.crossref_analysis()
            
            mock_logger.error.assert_any_call("Error checking package malicious-package: Search error")