import pytest
from datetime import datetime, timezone, timedelta
from src.providers.storage.database_storage import DatabaseStorage
from src.core.entities import ScanResult, ScanStatus, MaliciousPackage

@pytest.fixture
def db_storage():
    return DatabaseStorage(database_path=":memory:", in_memory=True, connection_timeout=5.0)

@pytest.fixture
def sample_packages():
    return [
        MaliciousPackage(
            name="pkg-a",
            version="1.0.0",
            ecosystem="PyPI",
            package_url="pkg:pypi/pkg-a@1.0.0",
            advisory_id="ADV-1",
            summary="Test package A",
            details="Details A",
            aliases=[],
            affected_versions=["1.0.0"],
            database_specific={},
            published_at=datetime.now(timezone.utc) - timedelta(days=1),
            modified_at=datetime.now(timezone.utc)
        ),
        MaliciousPackage(
            name="pkg-b",
            version="2.0.0",
            ecosystem="npm",
            package_url="pkg:npm/pkg-b@2.0.0",
            advisory_id="ADV-2",
            summary="Test package B",
            details="Details B",
            aliases=[],
            affected_versions=["2.0.0"],
            database_specific={},
            published_at=datetime.now(timezone.utc) - timedelta(days=2),
            modified_at=datetime.now(timezone.utc)
        )
    ]

@pytest.fixture
def scan_result_factory(sample_packages):
    def _make(scan_id: str, status=ScanStatus.SUCCESS, with_findings=False):
        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            status=status,
            packages_scanned=42,
            malicious_packages_found=sample_packages if with_findings else [],
            packages_blocked=[p.name for p in sample_packages] if with_findings else [],
            malicious_packages_list=sample_packages if with_findings else [],
            errors=[],
            execution_duration_seconds=1.23
        )
    return _make

@pytest.mark.asyncio
async def test_store_and_retrieve_scan_results(db_storage, scan_result_factory):
    sr1 = scan_result_factory("scan-1", with_findings=True)
    sr2 = scan_result_factory("scan-2", with_findings=False)
    assert await db_storage.store_scan_result(sr1) is True
    assert await db_storage.store_scan_result(sr2) is True

    results = await db_storage.get_scan_results()
    ids = {r.scan_id for r in results}
    assert {"scan-1", "scan-2"} <= ids

@pytest.mark.asyncio
async def test_update_existing_scan_result(db_storage, scan_result_factory):
    sr = scan_result_factory("scan-3", with_findings=False)
    await db_storage.store_scan_result(sr)
    # Update with findings
    sr_updated = scan_result_factory("scan-3", with_findings=True)
    await db_storage.store_scan_result(sr_updated)
    results = await db_storage.get_scan_results(scan_id="scan-3")
    assert len(results) == 1
    r = results[0]
    assert len(r.malicious_packages_found) == 2
    assert len(r.packages_blocked) == 2

@pytest.mark.asyncio
async def test_limit_and_scan_id_filters(db_storage, scan_result_factory):
    for i in range(5):
        await db_storage.store_scan_result(scan_result_factory(f"scan-{i}"))
    limited = await db_storage.get_scan_results(limit=3)
    assert len(limited) == 3
    specific = await db_storage.get_scan_results(scan_id="scan-2")
    assert len(specific) == 1
    assert specific[0].scan_id == "scan-2"

@pytest.mark.asyncio
async def test_known_malicious_packages(db_storage, scan_result_factory):
    await db_storage.store_scan_result(scan_result_factory("scan-x", with_findings=True))
    pkgs = await db_storage.get_known_malicious_packages()
    names = {p.name for p in pkgs}
    assert {"pkg-a", "pkg-b"} <= names

@pytest.mark.asyncio
async def test_health_check(db_storage):
    assert await db_storage.health_check() is True
