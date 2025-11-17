"""Health Management Use Case for checking service health status."""

import logging
from typing import Any, Dict


class HealthManagementUseCase:
    """Use case for health management operations."""

    def __init__(self, services: Dict[str, Any]):
        """
        Initialize the health management use case.

        Args:
            services: Dictionary of services to check health for
        """
        self.services = services
        self.logger = logging.getLogger(__name__)

    async def get_service_health_status(self) -> Dict[str, Any]:
        """
        Check health of all services.

        Returns:
            Dictionary containing health status for each service
        """
        try:
            self.logger.debug("Checking service health...")

            health_results = {}

            if self.services:
                # Check service health
                for service_name, service in self.services.items():
                    if service_name == "scanner":
                        continue  # Skip scanner as it's not a direct service

                    try:
                        health = await service.health_check()

                        # Handle dict response (services returning detailed info)
                        if isinstance(health, dict):
                            is_healthy = health.get("healthy", True)
                            health_results[service_name] = {
                                "healthy": is_healthy,
                                "status": "healthy" if is_healthy else "unhealthy",
                                "details": health,  # Pass full dict to CLI for formatting
                            }
                        else:
                            # Handle boolean response (simple health check)
                            health_results[service_name] = {
                                "healthy": bool(health),
                                "status": "healthy" if health else "unhealthy",
                                "details": (
                                    "Service is responding normally"
                                    if health
                                    else "Service is not responding"
                                ),
                            }

                        self.logger.debug(
                            f"Service {service_name}: {'healthy' if health_results[service_name]['healthy'] else 'unhealthy'}"
                        )
                    except Exception as e:
                        health_results[service_name] = {
                            "healthy": False,
                            "status": "error",
                            "details": str(e),
                        }
                        self.logger.error(f"Error checking {service_name} health: {e}")

            # Calculate overall health
            healthy_count = sum(1 for h in health_results.values() if h["healthy"])
            total_count = len(health_results)
            overall_healthy = healthy_count == total_count and total_count > 0

            result = {
                "success": True,
                "overall_healthy": overall_healthy,
                "healthy_count": healthy_count,
                "total_count": total_count,
                "services": health_results,
            }

            self.logger.debug(
                f"Health check complete: {healthy_count}/{total_count} services healthy"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error during health check: {e}")
            return {
                "success": False,
                "error": str(e),
                "overall_healthy": False,
                "healthy_count": 0,
                "total_count": 0,
                "services": {},
            }
