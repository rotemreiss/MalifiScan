from datetime import datetime, timezone

import pytest

from src.core.entities import MaliciousPackage, ScanResult, ScanStatus
from src.core.interfaces.packages_registry_service import PackagesRegistryService
from src.core.usecases.scan_results import ScanResultsManager
from src.providers.storage.database_storage import DatabaseStorage


class DummyRegistryService(PackagesRegistryService):
    async def block_packages(self, packages):
        return []

    async def block_package(self, package):
        return False

    async def check_existing_packages(self, packages):
        return []

    async def unblock_packages(self, packages):
        return []

    async def search_packages(self, package_name: str, ecosystem: str):
        return []

    async def is_package_blocked(self, package):
        return False

    async def health_check(self):
        return True

    async def close(self):
        return None

    def get_registry_name(self) -> str:
        return "dummy"

    async def discover_repositories_by_ecosystem(self, ecosystem: str):
        return ["dummy-repo"]


@pytest.fixture
def db_storage():
    return DatabaseStorage(database_path=":memory:", in_memory=True)


@pytest.fixture
def scan_result(db_storage):
    def _make(scan_id: str, packages=None):
        packages = packages or []
        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            status=ScanStatus.SUCCESS,
            packages_scanned=10,
            malicious_packages_found=packages,
            packages_blocked=[p.name for p in packages],
            malicious_packages_list=packages,
            errors=[],
            execution_duration_seconds=0.5,
        )

    return _make


@pytest.mark.asyncio
async def test_full_scan_result_flow(db_storage, scan_result):
    registry_service = DummyRegistryService()
    use_case = ScanResultsManager(db_storage, registry_service)

    # Create malicious packages
    mp = MaliciousPackage(
        name="malx",
        version="1.2.3",
        ecosystem="PyPI",
        package_url="pkg:pypi/malx@1.2.3",
        advisory_id="ADV-X",
        summary="Bad",
        details="Details",
        aliases=[],
        affected_versions=["1.2.3"],
        database_specific={},
        published_at=None,
        modified_at=None,
    )

    sr = scan_result("scan-int-1", packages=[mp])
    assert await db_storage.store_scan_result(sr) is True

    fetched = await db_storage.get_scan_results(scan_id="scan-int-1")
    assert len(fetched) == 1
    assert fetched[0].scan_id == "scan-int-1"

    # Use case path (if any summarization or processing added later)
    summaries = await use_case.get_recent_scans(limit=5)
    assert any(s.scan_id == "scan-int-1" for s in summaries)


@pytest.mark.asyncio
async def test_multiple_scan_results_and_limit(db_storage, scan_result):
    for i in range(6):
        await db_storage.store_scan_result(scan_result(f"scan-int-{i}"))
    fetched_all = await db_storage.get_scan_results()
    assert len(fetched_all) == 6
    limited = await db_storage.get_scan_results(limit=3)
    assert len(limited) == 3
