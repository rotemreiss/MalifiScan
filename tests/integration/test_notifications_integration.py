"""Integration tests for notification functionality."""

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.entities import MaliciousPackage, NotificationEvent, NotificationLevel
from src.core.usecases.security_analysis import SecurityAnalysisUseCase
from src.factories.service_factory import ServiceFactory
from src.providers.notifications.msteams_notifier import MSTeamsNotifier


@pytest.mark.integration
@pytest.mark.asyncio
async def test_msteams_notifier_integration():
    """Test MS Teams notifier integration."""
    # Define test configuration with MS Teams
    test_config_with_msteams = {
        "notification_service": {
            "type": "msteams",
            "enabled": True,
            "config": {"webhook_url": "https://example.webhook.office.com/test"},
        }
    }
    with patch("src.config.config_loader.ConfigLoader.load") as mock_load:
        mock_load.return_value = MagicMock(**test_config_with_msteams)

        # Mock the config object attributes
        config = MagicMock()
        for key, value in test_config_with_msteams.items():
            if isinstance(value, dict):
                setattr(config, key, MagicMock(**value))
            else:
                setattr(config, key, value)

        factory = ServiceFactory(config)
        notification_service = factory.create_notification_service()
        # Extract webhook URL from config
        webhook_url = test_config_with_msteams["notification_service"]["config"][
            "webhook_url"
        ]
        # Verify it's an MS Teams notifier
        assert isinstance(notification_service, MSTeamsNotifier)
        assert notification_service.webhook_url == webhook_url

    @pytest.mark.asyncio
    async def test_service_factory_creates_null_notifier_when_disabled(
        self, test_config_with_disabled_notifications
    ):
        """Test that service factory creates null notifier when notifications disabled."""
        with patch("src.config.config_loader.ConfigLoader.load") as mock_load:
            mock_load.return_value = MagicMock(
                **test_config_with_disabled_notifications
            )

            # Mock the config object attributes
            config = MagicMock()
            for key, value in test_config_with_disabled_notifications.items():
                if isinstance(value, dict):
                    setattr(config, key, MagicMock(**value))
                else:
                    setattr(config, key, value)

            factory = ServiceFactory(config)
            notification_service = factory.create_notification_service()

            # Verify it's a null notifier
            from src.providers.notifications.null_notifier import NullNotifier

            assert isinstance(notification_service, NullNotifier)

    @pytest.mark.asyncio
    async def test_service_factory_fallback_to_null_on_error(
        self, test_config_with_msteams
    ):
        """Test that service factory falls back to null notifier on MS Teams creation error."""
        with patch.dict(os.environ, {}, clear=True):  # No webhook URL
            with patch("src.config.config_loader.ConfigLoader.load") as mock_load:
                mock_load.return_value = MagicMock(**test_config_with_msteams)

                # Mock the config object attributes
                config = MagicMock()
                for key, value in test_config_with_msteams.items():
                    if isinstance(value, dict):
                        setattr(config, key, MagicMock(**value))
                    else:
                        setattr(config, key, value)

                factory = ServiceFactory(config)
                notification_service = factory.create_notification_service()

                # Should fall back to null notifier due to missing webhook URL
                from src.providers.notifications.null_notifier import NullNotifier

                assert isinstance(notification_service, NullNotifier)

    @pytest.mark.asyncio
    async def test_security_analysis_sends_notification_on_critical_findings(self):
        """Test that security analysis sends notifications when critical packages are found."""
        webhook_url = "https://prod-crit.powerplatform.com/powerautomate/workflows/critical-test/triggers/manual/paths/invoke"

        with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
            # Mock services
            mock_packages_feed = AsyncMock()
            mock_registry_service = AsyncMock()
            mock_storage_service = AsyncMock()
            mock_notification_service = AsyncMock()

            # Configure mock returns
            mock_packages_feed.fetch_malicious_packages.return_value = [
                MaliciousPackage(
                    ecosystem="npm",
                    name="malicious-test-package",
                    version="1.0.0",
                    summary="Test malicious package",
                    details="Test vulnerability",
                    modified_at=datetime.now(timezone.utc),
                )
            ]

            mock_registry_service.health_check.return_value = True
            mock_registry_service.get_registry_name.return_value = "TestRegistry"
            mock_registry_service.search_package.return_value = {
                "found": True,
                "package_info": {"name": "malicious-test-package", "version": "1.0.0"},
            }
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

            # Verify notification event structure
            notification_call = mock_notification_service.send_notification.call_args[
                0
            ][0]
            assert isinstance(notification_call, NotificationEvent)
            assert notification_call.level == NotificationLevel.CRITICAL
            assert len(notification_call.affected_packages) > 0

    @pytest.mark.asyncio
    async def test_security_analysis_no_notification_when_disabled(self):
        """Test that security analysis doesn't send notifications when disabled."""
        # Mock services
        mock_packages_feed = AsyncMock()
        mock_registry_service = AsyncMock()
        mock_storage_service = AsyncMock()
        mock_notification_service = AsyncMock()

        # Configure mock returns
        mock_packages_feed.fetch_malicious_packages.return_value = [
            MaliciousPackage(
                ecosystem="npm",
                name="malicious-test-package",
                version="1.0.0",
                summary="Test malicious package",
                details="Test vulnerability",
                modified_at=datetime.now(timezone.utc),
            )
        ]

        mock_registry_service.health_check.return_value = True
        mock_registry_service.get_registry_name.return_value = "TestRegistry"
        mock_registry_service.search_package.return_value = {
            "found": True,
            "package_info": {"name": "malicious-test-package", "version": "1.0.0"},
        }
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
    async def test_security_analysis_no_notification_when_no_critical_findings(self):
        """Test that security analysis doesn't send notifications when no critical findings."""
        webhook_url = "https://prod-nf.powerplatform.com/powerautomate/workflows/no-findings-test/triggers/manual/paths/invoke"

        with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
            # Mock services
            mock_packages_feed = AsyncMock()
            mock_registry_service = AsyncMock()
            mock_storage_service = AsyncMock()
            mock_notification_service = AsyncMock()

            # Configure mock returns - no malicious packages found
            mock_packages_feed.fetch_malicious_packages.return_value = [
                MaliciousPackage(
                    ecosystem="npm",
                    name="not-in-registry-package",
                    version="1.0.0",
                    summary="Test malicious package",
                    details="Test vulnerability",
                    modified_at=datetime.now(timezone.utc),
                )
            ]

            mock_registry_service.health_check.return_value = True
            mock_registry_service.get_registry_name.return_value = "TestRegistry"
            mock_registry_service.search_package.return_value = {
                "found": False  # Package not found in registry
            }
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
    async def test_notification_error_handling_in_security_analysis(self):
        """Test that notification errors don't break security analysis."""
        webhook_url = "https://prod-err.powerplatform.com/powerautomate/workflows/error-test/triggers/manual/paths/invoke"

        with patch.dict(os.environ, {"MSTEAMS_WEBHOOK_URL": webhook_url}):
            # Mock services
            mock_packages_feed = AsyncMock()
            mock_registry_service = AsyncMock()
            mock_storage_service = AsyncMock()
            mock_notification_service = AsyncMock()

            # Configure mock returns
            mock_packages_feed.fetch_malicious_packages.return_value = [
                MaliciousPackage(
                    ecosystem="npm",
                    name="malicious-test-package",
                    version="1.0.0",
                    summary="Test malicious package",
                    details="Test vulnerability",
                    modified_at=datetime.now(timezone.utc),
                )
            ]

            mock_registry_service.health_check.return_value = True
            mock_registry_service.get_registry_name.return_value = "TestRegistry"
            mock_registry_service.search_package.return_value = {
                "found": True,
                "package_info": {"name": "malicious-test-package", "version": "1.0.0"},
            }
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
            assert "notification_error" in result  # Error recorded
            mock_notification_service.send_notification.assert_called_once()
