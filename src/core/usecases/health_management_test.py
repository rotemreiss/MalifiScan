"""Tests for health_management use case."""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from src.core.usecases.health_management import HealthManagementUseCase


class TestHealthManagementUseCase:
    """Test cases for HealthManagementUseCase."""

    @pytest.fixture
    def mock_logger(self):
        """Mock logger for testing."""
        with patch('src.core.usecases.health_management.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            yield mock_logger

    @pytest.fixture
    def mock_healthy_service(self):
        """Mock service that is healthy."""
        service = Mock()
        service.health_check = AsyncMock(return_value=True)
        return service

    @pytest.fixture
    def mock_unhealthy_service(self):
        """Mock service that is unhealthy."""
        service = Mock()
        service.health_check = AsyncMock(return_value=False)
        return service

    @pytest.fixture
    def mock_service_with_exception(self):
        """Mock service that raises an exception during health check."""
        service = Mock()
        service.health_check = AsyncMock(side_effect=Exception("Connection timeout"))
        return service

    @pytest.fixture
    def mock_service_without_health_check(self):
        """Mock service without health_check method."""
        service = Mock(spec=[])  # Empty spec means no methods
        return service

    def test_init_with_empty_services(self, mock_logger):
        """Test initialization with empty services dictionary."""
        services = {}
        use_case = HealthManagementUseCase(services)
        
        assert use_case.services == services
        assert use_case.logger is not None

    def test_init_with_services(self, mock_logger, mock_healthy_service):
        """Test initialization with services dictionary."""
        services = {"service1": mock_healthy_service}
        use_case = HealthManagementUseCase(services)
        
        assert use_case.services == services
        assert "service1" in use_case.services

    @pytest.mark.asyncio
    async def test_get_service_health_status_empty_services(self, mock_logger):
        """Test health check with no services."""
        use_case = HealthManagementUseCase({})
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False  # False when no services
        assert result["healthy_count"] == 0
        assert result["total_count"] == 0
        assert result["services"] == {}
        
        mock_logger.info.assert_called_with("Health check complete: 0/0 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_single_healthy_service(self, mock_logger, mock_healthy_service):
        """Test health check with single healthy service."""
        services = {"db": mock_healthy_service}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is True
        assert result["healthy_count"] == 1
        assert result["total_count"] == 1
        assert result["services"]["db"]["healthy"] is True
        assert result["services"]["db"]["status"] == "healthy"
        assert "responding normally" in result["services"]["db"]["details"]
        
        mock_healthy_service.health_check.assert_called_once()
        mock_logger.info.assert_called_with("Health check complete: 1/1 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_single_unhealthy_service(self, mock_logger, mock_unhealthy_service):
        """Test health check with single unhealthy service."""
        services = {"api": mock_unhealthy_service}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 1
        assert result["services"]["api"]["healthy"] is False
        assert result["services"]["api"]["status"] == "unhealthy"
        assert "not responding" in result["services"]["api"]["details"]
        
        mock_unhealthy_service.health_check.assert_called_once()
        mock_logger.info.assert_called_with("Health check complete: 0/1 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_mixed_services(self, mock_logger, mock_healthy_service, mock_unhealthy_service):
        """Test health check with mix of healthy and unhealthy services."""
        services = {
            "db": mock_healthy_service,
            "api": mock_unhealthy_service
        }
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False  # Not all services are healthy
        assert result["healthy_count"] == 1
        assert result["total_count"] == 2
        assert result["services"]["db"]["healthy"] is True
        assert result["services"]["api"]["healthy"] is False
        
        mock_healthy_service.health_check.assert_called_once()
        mock_unhealthy_service.health_check.assert_called_once()
        mock_logger.info.assert_called_with("Health check complete: 1/2 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_multiple_healthy_services(self, mock_logger):
        """Test health check with multiple healthy services."""
        # Create multiple healthy services
        service1 = Mock()
        service1.health_check = AsyncMock(return_value=True)
        service2 = Mock()
        service2.health_check = AsyncMock(return_value=True)
        service3 = Mock()
        service3.health_check = AsyncMock(return_value=True)
        
        services = {
            "database": service1,
            "cache": service2,
            "queue": service3
        }
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is True
        assert result["healthy_count"] == 3
        assert result["total_count"] == 3
        assert all(service_status["healthy"] for service_status in result["services"].values())
        
        service1.health_check.assert_called_once()
        service2.health_check.assert_called_once()
        service3.health_check.assert_called_once()
        mock_logger.info.assert_called_with("Health check complete: 3/3 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_service_exception(self, mock_logger, mock_service_with_exception):
        """Test health check when service raises exception."""
        services = {"failing_service": mock_service_with_exception}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 1
        assert result["services"]["failing_service"]["healthy"] is False
        assert result["services"]["failing_service"]["status"] == "error"
        assert "Connection timeout" in result["services"]["failing_service"]["details"]
        
        mock_service_with_exception.health_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_service_health_status_service_without_health_check(self, mock_logger, mock_service_without_health_check):
        """Test health check when service doesn't have health_check method."""
        services = {"invalid_service": mock_service_without_health_check}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 1
        assert result["services"]["invalid_service"]["healthy"] is False
        assert result["services"]["invalid_service"]["status"] == "error"
        assert "health_check" in result["services"]["invalid_service"]["details"]

    @pytest.mark.asyncio
    async def test_get_service_health_status_mixed_with_exceptions(self, mock_logger, mock_healthy_service, mock_service_with_exception):
        """Test health check with mix of healthy services and services with exceptions."""
        services = {
            "good_service": mock_healthy_service,
            "bad_service": mock_service_with_exception
        }
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 1
        assert result["total_count"] == 2
        assert result["services"]["good_service"]["healthy"] is True
        assert result["services"]["bad_service"]["healthy"] is False

    @pytest.mark.asyncio
    async def test_get_service_health_status_use_case_exception(self, mock_logger):
        """Test when the entire health check process fails with an exception."""
        # Create a use case that will fail during the logging call
        services = {"test": Mock()}
        use_case = HealthManagementUseCase(services)
        
        # Mock logger.info to raise an exception to trigger the outer catch block
        mock_logger.info.side_effect = Exception("Logging failed")
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is False
        assert result["error"] == "Logging failed"
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 0
        assert result["services"] == {}
        
        mock_logger.error.assert_called_with("Error during health check: Logging failed")

    @pytest.mark.asyncio
    async def test_get_service_health_status_service_returns_invalid_format(self, mock_logger):
        """Test health check when service returns invalid health status format."""
        # The implementation stores the raw return value in the "healthy" field
        invalid_service = Mock()
        invalid_service.health_check = AsyncMock(return_value=0)  # Falsy value
        
        services = {"invalid_format_service": invalid_service}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 1
        assert result["services"]["invalid_format_service"]["healthy"] == 0  # Raw value stored

    @pytest.mark.asyncio
    async def test_get_service_health_status_service_returns_none(self, mock_logger):
        """Test health check when service returns None."""
        none_service = Mock()
        none_service.health_check = AsyncMock(return_value=None)
        
        services = {"none_service": none_service}
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False
        assert result["healthy_count"] == 0
        assert result["total_count"] == 1
        assert result["services"]["none_service"]["healthy"] is None  # Raw value stored

    @pytest.mark.asyncio
    async def test_get_service_health_status_large_number_of_services(self, mock_logger):
        """Test health check with a large number of services."""
        # Create 10 services, 7 healthy and 3 unhealthy
        services = {}
        for i in range(7):
            service = Mock()
            service.health_check = AsyncMock(return_value=True)
            services[f"healthy_service_{i}"] = service
        
        for i in range(3):
            service = Mock()
            service.health_check = AsyncMock(return_value=False)
            services[f"unhealthy_service_{i}"] = service
        
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["overall_healthy"] is False  # Not all services healthy
        assert result["healthy_count"] == 7
        assert result["total_count"] == 10
        assert len(result["services"]) == 10
        
        # Verify all services were checked
        for service in services.values():
            service.health_check.assert_called_once()
        
        mock_logger.info.assert_called_with("Health check complete: 7/10 services healthy")

    @pytest.mark.asyncio
    async def test_get_service_health_status_concurrent_execution(self, mock_logger):
        """Test that health checks are executed sequentially as per implementation."""
        # The implementation doesn't use asyncio.gather, so services are checked sequentially
        slow_service1 = Mock()
        slow_service2 = Mock()
        
        async def slow_health_check():
            await asyncio.sleep(0.01)  # Very small delay
            return True
        
        slow_service1.health_check = slow_health_check
        slow_service2.health_check = slow_health_check
        
        services = {
            "slow1": slow_service1,
            "slow2": slow_service2
        }
        
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["healthy_count"] == 2
        assert result["total_count"] == 2

    @pytest.mark.asyncio
    async def test_get_service_health_status_skip_scanner_service(self, mock_logger):
        """Test that services named 'scanner' are skipped."""
        normal_service = Mock()
        normal_service.health_check = AsyncMock(return_value=True)
        
        scanner_service = Mock()
        scanner_service.health_check = AsyncMock(return_value=True)
        
        services = {
            "normal": normal_service,
            "scanner": scanner_service  # This should be skipped
        }
        
        use_case = HealthManagementUseCase(services)
        
        result = await use_case.get_service_health_status()
        
        assert result["success"] is True
        assert result["healthy_count"] == 1  # Only normal service counted
        assert result["total_count"] == 1
        assert "normal" in result["services"]
        assert "scanner" not in result["services"]  # Scanner should be skipped
        
        normal_service.health_check.assert_called_once()
        scanner_service.health_check.assert_not_called()  # Scanner not checked