"""Unit tests for MemoryFeed provider."""

import pytest

from src.providers.feeds.memory_feed import MemoryFeed


class TestMemoryFeed:
    """Test the MemoryFeed provider."""

    def test_memory_feed_initialization_empty(self):
        """Test MemoryFeed initialization with no packages."""
        feed = MemoryFeed()

        assert feed.get_package_count() == 0
        assert str(feed) == "MemoryFeed(0 packages, 0 ecosystems)"

    def test_memory_feed_initialization_with_packages(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test MemoryFeed initialization with packages."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        assert feed.get_package_count() == 2
        assert str(feed) == "MemoryFeed(2 packages, 2 ecosystems)"

    @pytest.mark.asyncio
    async def test_get_available_ecosystems(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test getting available ecosystems."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        ecosystems = await feed.get_available_ecosystems()

        assert len(ecosystems) == 2
        assert "npm" in ecosystems
        assert "pypi" in ecosystems
        assert ecosystems == ["npm", "pypi"]  # Should be sorted

    @pytest.mark.asyncio
    async def test_fetch_all_packages(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test fetching all packages without filters."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        result = await feed.fetch_malicious_packages()

        assert len(result) == 2
        assert result[0].name == "test-pypi-pkg"  # From sample_malicious_package (PyPI)
        assert (
            result[1].name == "test-critical-npm"
        )  # From sample_npm_malicious_package

    @pytest.mark.asyncio
    async def test_fetch_packages_by_ecosystem(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test fetching packages filtered by ecosystem."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        # Filter by npm
        npm_packages = await feed.fetch_malicious_packages(ecosystems=["npm"])
        assert len(npm_packages) == 1
        assert (
            npm_packages[0].name == "test-critical-npm"
        )  # Updated to match consolidated fixture
        assert npm_packages[0].ecosystem == "npm"

        # Filter by pypi (note: sample_malicious_package uses "PyPI" capitalized)
        pypi_packages = await feed.fetch_malicious_packages(ecosystems=["PyPI"])
        assert len(pypi_packages) == 1
        assert (
            pypi_packages[0].name == "test-pypi-pkg"
        )  # Updated to match consolidated fixture
        assert pypi_packages[0].ecosystem == "PyPI"

        # Filter by non-existent ecosystem
        none_packages = await feed.fetch_malicious_packages(ecosystems=["maven"])
        assert len(none_packages) == 0

    @pytest.mark.asyncio
    async def test_fetch_packages_with_limit(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test fetching packages with max_packages limit."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        # Limit to 1 package
        result = await feed.fetch_malicious_packages(max_packages=1)
        assert len(result) == 1

        # Limit to 2 packages
        result = await feed.fetch_malicious_packages(max_packages=2)
        assert len(result) == 2

        # Limit higher than available packages
        result = await feed.fetch_malicious_packages(max_packages=10)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check."""
        feed = MemoryFeed()

        result = await feed.health_check()
        assert result is True

    def test_add_package(self, sample_malicious_package):
        """Test adding a single package."""
        feed = MemoryFeed()

        feed.add_package(sample_malicious_package)

        assert feed.get_package_count() == 1
        assert str(feed) == "MemoryFeed(1 packages, 1 ecosystems)"

    def test_add_packages(self, sample_malicious_package, sample_npm_malicious_package):
        """Test adding multiple packages."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed()

        feed.add_packages(packages)

        assert feed.get_package_count() == 2
        assert str(feed) == "MemoryFeed(2 packages, 2 ecosystems)"

    def test_clear(self, sample_malicious_package, sample_npm_malicious_package):
        """Test clearing all packages."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        assert feed.get_package_count() == 2

        feed.clear()

        assert feed.get_package_count() == 0
        assert str(feed) == "MemoryFeed(0 packages, 0 ecosystems)"

    @pytest.mark.asyncio
    async def test_ecosystem_filtering_case_insensitive(
        self, sample_malicious_package, sample_npm_malicious_package
    ):
        """Test ecosystem filtering is case insensitive."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        # Test uppercase ecosystem filter
        result = await feed.fetch_malicious_packages(ecosystems=["NPM"])
        assert len(result) == 1
        assert result[0].name == "test-critical-npm"

        # Test mixed case ecosystem filter (PyPI is already capitalized in fixture)
        result = await feed.fetch_malicious_packages(ecosystems=["pypi"])
        assert len(result) == 1
        assert result[0].name == "test-pypi-pkg"

    def test_repr(self, sample_malicious_package, sample_npm_malicious_package):
        """Test string representation."""
        packages = [sample_malicious_package, sample_npm_malicious_package]
        feed = MemoryFeed(packages=packages)

        assert repr(feed) == "MemoryFeed(packages=2)"
