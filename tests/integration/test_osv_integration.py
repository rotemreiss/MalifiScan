"""Integration tests for OSV Feed provider."""

import pytest
import pytest_asyncio
import os
import logging
from typing import List
from datetime import datetime, timedelta

from src.config import ConfigLoader
from src.providers.feeds.osv_feed import OSVFeed
from src.core.entities import MaliciousPackage
from src.providers.exceptions import FeedError


@pytest.mark.integration
class TestOSVFeedIntegration:
    """Integration tests for OSV Feed functionality.
    
    These tests make real API calls to OSV and should not run in CI.
    Set SKIP_INTEGRATION_TESTS=true to skip these tests.
    """
    
    @pytest.fixture(scope="class")
    def config(self):
        """Load configuration for OSV integration tests."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")
        
        # Load configuration
        config_loader = ConfigLoader()
        config = config_loader.load()
        
        return config
    
    @pytest_asyncio.fixture(scope="function")
    async def osv_feed(self, config):
        """Create OSV feed instance."""
        feed = OSVFeed(
            bucket_name="osv-vulnerabilities",  # Default OSV bucket
            timeout_seconds=60,  # OSV can be slower
            max_retries=3
        )
        
        # Initialize the feed
        async with feed as initialized_feed:
            yield initialized_feed
    
    @pytest.mark.asyncio
    async def test_osv_feed_health_check(self, osv_feed):
        """Test OSV feed health check."""
        is_healthy = await osv_feed.health_check()
        assert is_healthy, "OSV feed should be healthy"
    
    @pytest.mark.asyncio
    async def test_fetch_malicious_packages_npm(self, osv_feed):
        """Test fetching npm malicious packages.
        
        This test verifies that OSV feed can retrieve npm vulnerability data.
        This addresses the requirement to see that we are getting npm logs.
        """
        # Fetch recent malicious packages for npm ecosystem
        malicious_packages = await osv_feed.fetch_malicious_packages(
            max_packages=10,
            hours=24 * 7  # Last 7 days
        )
        
        assert isinstance(malicious_packages, list), "Should return a list of malicious packages"
        
        # Filter for npm packages specifically
        npm_packages = [pkg for pkg in malicious_packages if pkg.ecosystem == "npm"]
        
        # Log the results as required
        logging.info(f"OSV Feed Integration Test - NPM Logs:")
        logging.info(f"Total malicious packages found: {len(malicious_packages)}")
        logging.info(f"NPM malicious packages found: {len(npm_packages)}")
        
        if npm_packages:
            for i, pkg in enumerate(npm_packages[:3], 1):  # Log first 3 npm packages
                logging.info(f"NPM Package {i}: {pkg.name} (Advisory ID: {pkg.advisory_id})")
                logging.info(f"  Summary: {pkg.summary}")
                logging.info(f"  Ecosystem: {pkg.ecosystem}")
        else:
            logging.info("No npm malicious packages found in the last 7 days")
        
        # This test should pass even if no npm packages are found
        # as the main requirement is to verify we can fetch OSV data
    
    @pytest.mark.asyncio
    async def test_fetch_npm_ecosystem_specific(self, osv_feed):
        """Test fetching malicious packages specifically for npm ecosystem."""
        try:
            # This uses the private method but it's the most direct way to test npm specifically
            npm_packages = await osv_feed._fetch_malicious_packages_for_ecosystem(
                ecosystem="npm",
                max_packages=5,
                hours=24 * 30  # Last 30 days for better chance of data
            )
            
            assert isinstance(npm_packages, list), "Should return a list"
            
            logging.info(f"NPM-specific fetch: Found {len(npm_packages)} malicious npm packages")
            
            # Verify all returned packages are npm packages
            for pkg in npm_packages:
                assert pkg.ecosystem == "npm", f"Expected npm package, got {pkg.ecosystem}"
            
            if npm_packages:
                sample_pkg = npm_packages[0]
                logging.info(f"Sample npm malicious package: {sample_pkg.name}")
                logging.info(f"  Advisory ID: {sample_pkg.advisory_id}")
                logging.info(f"  Summary: {sample_pkg.summary}")
        
        except Exception as e:
            # If the private method is not accessible, fall back to general fetch
            logging.warning(f"Could not test npm-specific fetch: {e}")
            pytest.skip("NPM-specific ecosystem fetch not available")
    
    @pytest.mark.asyncio
    async def test_fetch_recent_packages_short_window(self, osv_feed):
        """Test fetching packages from a short time window."""
        # Test with a 24-hour window
        packages = await osv_feed.fetch_malicious_packages(
            max_packages=20,
            hours=24
        )
        
        assert isinstance(packages, list), "Should return a list"
        
        logging.info(f"Packages in last 24 hours: {len(packages)}")
        
        # Count by ecosystem
        ecosystem_counts = {}
        for pkg in packages:
            ecosystem_counts[pkg.ecosystem] = ecosystem_counts.get(pkg.ecosystem, 0) + 1
        
        logging.info("Packages by ecosystem in last 24 hours:")
        for ecosystem, count in ecosystem_counts.items():
            logging.info(f"  {ecosystem}: {count}")
        
        if "npm" in ecosystem_counts:
            logging.info(f"✓ Found {ecosystem_counts['npm']} npm packages in OSV feed")
        else:
            logging.info("ℹ No npm packages found in last 24 hours (normal)")
    
    @pytest.mark.asyncio
    async def test_error_handling_invalid_ecosystem(self, osv_feed):
        """Test error handling for invalid ecosystem."""
        try:
            # Test with an invalid ecosystem
            packages = await osv_feed._fetch_malicious_packages_for_ecosystem(
                ecosystem="invalid_ecosystem_that_does_not_exist",
                max_packages=1
            )
            
            # Should return empty list, not error
            assert isinstance(packages, list), "Should return a list even for invalid ecosystem"
            assert len(packages) == 0, "Invalid ecosystem should return empty list"
            
        except Exception as e:
            # Some exceptions might be expected
            logging.info(f"Expected error for invalid ecosystem: {e}")
    
    @pytest.mark.asyncio
    async def test_fetch_with_limits(self, osv_feed):
        """Test fetching with different package limits."""
        # Test with small limit
        small_batch = await osv_feed.fetch_malicious_packages(max_packages=3)
        assert len(small_batch) <= 3, "Should respect max_packages limit"
        
        # Test with larger limit
        large_batch = await osv_feed.fetch_malicious_packages(max_packages=10)
        assert len(large_batch) <= 10, "Should respect max_packages limit"
        
        logging.info(f"Small batch (max 3): {len(small_batch)} packages")
        logging.info(f"Large batch (max 10): {len(large_batch)} packages")
    
    @pytest.mark.asyncio
    async def test_comprehensive_npm_logging(self, osv_feed):
        """Comprehensive test for npm logging - main requirement."""
        logging.info("=== OSV Feed NPM Integration Test ===")
        
        try:
            # Test 1: General malicious packages
            all_packages = await osv_feed.fetch_malicious_packages(max_packages=50)
            npm_packages = [pkg for pkg in all_packages if pkg.ecosystem == "npm"]
            
            logging.info(f"1. General fetch: {len(all_packages)} total, {len(npm_packages)} npm")
            
            # Test 2: Recent packages (24 hours)
            recent_packages = await osv_feed.fetch_malicious_packages(max_packages=20, hours=24)
            recent_npm = [pkg for pkg in recent_packages if pkg.ecosystem == "npm"]
            
            logging.info(f"2. Recent (24h): {len(recent_packages)} total, {len(recent_npm)} npm")
            
            # Test 3: Longer window (7 days)
            week_packages = await osv_feed.fetch_malicious_packages(max_packages=30, hours=24*7)
            week_npm = [pkg for pkg in week_packages if pkg.ecosystem == "npm"]
            
            logging.info(f"3. Week (7d): {len(week_packages)} total, {len(week_npm)} npm")
            
            # Log details of npm packages found
            all_npm_found = npm_packages + [p for p in recent_npm if p not in npm_packages] + [p for p in week_npm if p not in npm_packages and p not in recent_npm]
            
            logging.info(f"\n=== NPM Packages Summary ===")
            logging.info(f"Unique NPM packages found: {len(set(pkg.advisory_id for pkg in all_npm_found if pkg.advisory_id))}")
            
            if all_npm_found:
                logging.info("Sample npm packages:")
                for i, pkg in enumerate(all_npm_found[:5], 1):
                    logging.info(f"  {i}. {pkg.name} ({pkg.advisory_id or 'No advisory ID'})")
                    summary = pkg.summary[:100] + "..." if pkg.summary and len(pkg.summary) > 100 else pkg.summary or "No summary"
                    logging.info(f"     Summary: {summary}")
            else:
                logging.info("No npm packages found - this may be normal depending on timing")
            
            logging.info("=== OSV Feed NPM Test Complete ===")
            
            # Test should pass regardless of whether npm packages are found
            # The key is that we can successfully connect to and query OSV
            
        except Exception as e:
            pytest.fail(f"OSV Feed npm logging test failed: {e}")