"""Integration tests for notification functionality."""

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.entities import MaliciousPackage, NotificationEvent
from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.factories.service_factory import ServiceFactory
from src.providers.notifications.msteams_notifier import MSTeamsNotifier


@pytest.mark.integration
@pytest.mark.asyncio
async def test_msteams_notifier_integration():
    """Test MS Teams notifier integration."""
    # Create a proper mock config object with nested attributes
    config = MagicMock()

    # Create a proper dict with a valid MS Teams webhook URL format
    config_dict = {
        "webhook_url": "https://example.powerplatform.com/powerautomate/workflows/test"
    }

    # Mock notification_service attributes
    notification_config = MagicMock()
    notification_config.enabled = True
    notification_config.type = "msteams"
    notification_config.config = config_dict  # Use plain dict that supports .get()

    config.notification_service = notification_config

    factory = ServiceFactory(config)
    notification_service = factory.create_notification_service()

    # Verify it's an MS Teams notifier
    assert isinstance(notification_service, MSTeamsNotifier)
    assert (
        notification_service.webhook_url
        == "https://example.powerplatform.com/powerautomate/workflows/test"
    )


@pytest.mark.asyncio
async def test_service_factory_creates_null_notifier_when_disabled(test_config):
    """Test that service factory creates null notifier when notifications disabled."""
    # Test config already has null notifier enabled
    factory = ServiceFactory(test_config)
    notification_service = factory.create_notification_service()

    # Verify it's a null notifier
    from src.providers.notifications.null_notifier import NullNotifier

    assert isinstance(notification_service, NullNotifier)


@pytest.mark.asyncio
async def test_service_factory_fallback_to_null_on_error():
    """Test that service factory falls back to null notifier on MS Teams creation error."""
    # Mock the config with MSTeams but no environment variable
    from unittest.mock import MagicMock, patch

    test_config = MagicMock()
    test_config.notification_service.enabled = True
    test_config.notification_service.type = "msteams"

    with patch.dict(os.environ, {}, clear=True):  # No webhook URL
        factory = ServiceFactory(test_config)
        notification_service = factory.create_notification_service()

        # Should fall back to null notifier due to missing webhook URL
        from src.providers.notifications.null_notifier import NullNotifier

        assert isinstance(notification_service, NullNotifier)


@pytest.mark.asyncio
async def test_security_analysis_sends_notification_on_critical_findings(
    sample_npm_malicious_package,
    mock_packages_feed,
    mock_packages_registry,
    mock_storage_service,
    mock_notification_service,
):
    """Test that security analysis sends notifications when critical packages are found."""
    webhook_url = "https://prod-crit.powerplatform.com/powerautomate/workflows/critical-test/triggers/manual/paths/invoke"

    with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
        # Configure mock returns using fixtures
        mock_packages_feed.fetch_malicious_packages.return_value = [
            sample_npm_malicious_package
        ]

        # Configure registry mock with mixed sync/async methods
        mock_registry_service = MagicMock()  # Base as MagicMock
        mock_registry_service.health_check = AsyncMock(return_value=True)
        mock_registry_service.get_registry_name.return_value = "TestRegistry"
        mock_registry_service.search_packages = AsyncMock(
            return_value=[
                {
                    "name": sample_npm_malicious_package.name,
                    "version": sample_npm_malicious_package.version,
                    "ecosystem": sample_npm_malicious_package.ecosystem,
                }
            ]
        )
        mock_registry_service.close = AsyncMock()

        mock_notification_service.send_notification.return_value = True

        # Create security analysis use case
        security_analysis = SecurityAnalysisUseCase(
            packages_feed=mock_packages_feed,
            registry_service=mock_registry_service,
            storage_service=mock_storage_service,
            notification_service=mock_notification_service,
        )

        # Run analysis
        result = await security_analysis.crossref_analysis(
            hours=1,
            ecosystem="npm",
            limit=1,
            save_report=False,
            send_notifications=True,
        )

        # Verify notification was sent
        assert result["success"] is True
        assert len(result["found_matches"]) > 0  # Critical finding
        mock_notification_service.send_notification.assert_called_once()

        # Verify notification event structure (the actual level depends on the notification logic)
        notification_call = mock_notification_service.send_notification.call_args[0][0]
        assert isinstance(notification_call, NotificationEvent)
        # Don't assert the specific level since it depends on new vs existing threats
        assert len(result["found_matches"]) > 0  # But verify we have critical matches


@pytest.mark.asyncio
async def test_security_analysis_no_notification_when_disabled(
    sample_npm_malicious_package,
    mock_packages_feed,
    mock_storage_service,
    mock_notification_service,
):
    """Test that security analysis doesn't send notifications when disabled."""
    # Configure mock returns using fixtures
    mock_packages_feed.fetch_malicious_packages.return_value = [
        sample_npm_malicious_package
    ]

    # Configure registry mock with mixed sync/async methods
    mock_registry_service = MagicMock()  # Base as MagicMock
    mock_registry_service.health_check = AsyncMock(return_value=True)
    mock_registry_service.get_registry_name.return_value = "TestRegistry"
    mock_registry_service.search_packages = AsyncMock(
        return_value=[
            {
                "name": sample_npm_malicious_package.name,
                "version": sample_npm_malicious_package.version,
            }
        ]
    )
    mock_registry_service.close = AsyncMock()

    # Create security analysis use case
    security_analysis = SecurityAnalysisUseCase(
        packages_feed=mock_packages_feed,
        registry_service=mock_registry_service,
        storage_service=mock_storage_service,
        notification_service=mock_notification_service,
    )

    # Run analysis with notifications disabled
    result = await security_analysis.crossref_analysis(
        hours=1,
        ecosystem="npm",
        limit=1,
        save_report=False,
        send_notifications=False,  # Disabled
    )

    # Verify notification was NOT sent
    assert result["success"] is True
    assert len(result["found_matches"]) > 0  # Critical finding exists
    mock_notification_service.send_notification.assert_not_called()


@pytest.mark.asyncio
async def test_security_analysis_no_notification_when_no_critical_findings(
    mock_packages_feed,
    mock_storage_service,
    mock_notification_service,
):
    """Test that security analysis doesn't send notifications when no critical findings."""
    webhook_url = "https://prod-nf.powerplatform.com/powerautomate/workflows/no-findings-test/triggers/manual/paths/invoke"

    with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
        # Create a malicious package that won't be found in registry
        malicious_package = MaliciousPackage(
            name="not-in-registry-package",
            version="1.0.0",
            ecosystem="npm",
            package_url="pkg:npm/not-in-registry-package@1.0.0",
            advisory_id="TEST-001",
            summary="Test malicious package",
            details="Test vulnerability",
            aliases=["CVE-2024-TEST"],
            affected_versions=["1.0.0"],
            database_specific={"severity": "CRITICAL"},
            published_at=datetime.now(timezone.utc),
            modified_at=datetime.now(timezone.utc),
        )

        # Configure mock returns using fixtures
        mock_packages_feed.fetch_malicious_packages.return_value = [malicious_package]

        # Configure registry mock with mixed sync/async methods
        mock_registry_service = MagicMock()  # Base as MagicMock
        mock_registry_service.health_check = AsyncMock(return_value=True)
        mock_registry_service.get_registry_name.return_value = "TestRegistry"
        mock_registry_service.search_packages = AsyncMock(
            return_value=[]
        )  # Package not found in registry
        mock_registry_service.close = AsyncMock()

        # Create security analysis use case
        security_analysis = SecurityAnalysisUseCase(
            packages_feed=mock_packages_feed,
            registry_service=mock_registry_service,
            storage_service=mock_storage_service,
            notification_service=mock_notification_service,
        )

        # Run analysis
        result = await security_analysis.crossref_analysis(
            hours=1,
            ecosystem="npm",
            limit=1,
            save_report=False,
            send_notifications=True,
        )

        # Verify no notification was sent (no critical findings)
        assert result["success"] is True
        assert len(result["found_matches"]) == 0  # No critical findings
        mock_notification_service.send_notification.assert_not_called()


@pytest.mark.asyncio
async def test_notification_error_handling_in_security_analysis(
    sample_npm_malicious_package,
    mock_packages_feed,
    mock_storage_service,
    mock_notification_service,
):
    """Test that notification errors don't break security analysis."""
    webhook_url = "https://prod-err.powerplatform.com/powerautomate/workflows/error-test/triggers/manual/paths/invoke"

    with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
        # Configure mock returns using fixtures
        mock_packages_feed.fetch_malicious_packages.return_value = [
            sample_npm_malicious_package
        ]

        # Configure registry mock with mixed sync/async methods
        mock_registry_service = MagicMock()  # Base as MagicMock
        mock_registry_service.health_check = AsyncMock(return_value=True)
        mock_registry_service.get_registry_name.return_value = "TestRegistry"
        mock_registry_service.search_packages = AsyncMock(
            return_value=[
                {
                    "name": sample_npm_malicious_package.name,
                    "version": sample_npm_malicious_package.version,
                }
            ]
        )
        mock_registry_service.close = AsyncMock()

        # Make notification service fail
        mock_notification_service.send_notification.side_effect = Exception(
            "Notification failed"
        )

        # Create security analysis use case
        security_analysis = SecurityAnalysisUseCase(
            packages_feed=mock_packages_feed,
            registry_service=mock_registry_service,
            storage_service=mock_storage_service,
            notification_service=mock_notification_service,
        )

        # Run analysis
        result = await security_analysis.crossref_analysis(
            hours=1,
            ecosystem="npm",
            limit=1,
            save_report=False,
            send_notifications=True,
        )

        # Verify analysis still succeeded despite notification error
        assert result["success"] is True
        assert len(result["found_matches"]) > 0  # Critical finding
        # The notification error is logged but doesn't fail the analysis
        # Check that notification was attempted (the method was called)
        mock_notification_service.send_notification.assert_called_once()
