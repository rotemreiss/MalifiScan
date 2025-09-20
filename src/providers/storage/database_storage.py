"""Database storage provider using SQLAlchemy with SQLite."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, create_engine, text, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.sqlite import TEXT
import uuid

from src.core.interfaces import StorageService
from src.core.entities import ScanResult, MaliciousPackage, ScanStatus
from src.providers.exceptions import StorageError

logger = logging.getLogger(__name__)

# SQLAlchemy Base
Base = declarative_base()


class RegistryModel(Base):
    """SQLAlchemy model for package registries."""
    __tablename__ = 'registries'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    type = Column(String, nullable=False)  # 'jfrog', 'npm', 'pypi', etc.
    base_url = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan_results = relationship("ScanResultModel", back_populates="registry")
    blocked_packages = relationship("BlockedPackageModel", back_populates="registry")


class ScanResultModel(Base):
    """SQLAlchemy model for scan results."""
    __tablename__ = 'scan_results'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, nullable=False, index=True)  # Not unique anymore, can have multiple rows per scan
    registry_id = Column(String, ForeignKey('registries.id'), nullable=False)  # Which registry was scanned
    timestamp = Column(DateTime, nullable=False)
    status = Column(String, nullable=False)
    packages_scanned = Column(Integer, nullable=False)
    errors = Column(Text, nullable=True)  # JSON string
    execution_duration_seconds = Column(Float, nullable=True)
    
    # Relationships
    registry = relationship("RegistryModel", back_populates="scan_results")
    malicious_packages = relationship("MaliciousPackageModel", back_populates="scan_result")
    findings = relationship("FindingModel", back_populates="scan_result")
    blocked_packages = relationship("BlockedPackageModel", back_populates="scan_result")


class MaliciousPackageModel(Base):
    """SQLAlchemy model for malicious packages found during scans."""
    __tablename__ = 'malicious_packages'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String, ForeignKey('scan_results.id'), nullable=False)
    
    # Package information
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    ecosystem = Column(String, nullable=False)
    package_url = Column(String, nullable=True)
    
    # Advisory information
    advisory_id = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    aliases = Column(Text, nullable=True)  # JSON string
    affected_versions = Column(Text, nullable=True)  # JSON string
    database_specific = Column(Text, nullable=True)  # JSON string
    
    # Timestamps
    published_at = Column(DateTime, nullable=True)
    modified_at = Column(DateTime, nullable=True)
    
    # Relationship
    scan_result = relationship("ScanResultModel", back_populates="malicious_packages")
    blocked_packages = relationship("BlockedPackageModel", back_populates="malicious_package")
    findings = relationship("FindingModel", back_populates="malicious_package")


class FindingModel(Base):
    """SQLAlchemy model for findings - when malicious packages are detected in our registry."""
    __tablename__ = 'findings'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String, ForeignKey('scan_results.id'), nullable=False)
    malicious_package_id = Column(String, ForeignKey('malicious_packages.id'), nullable=False)
    
    # Timestamp
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan_result = relationship("ScanResultModel", back_populates="findings")
    malicious_package = relationship("MaliciousPackageModel", back_populates="findings")


class BlockedPackageModel(Base):
    """SQLAlchemy model for packages that were blocked during a scan."""
    __tablename__ = 'blocked_packages'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String, ForeignKey('scan_results.id'), nullable=False)
    registry_id = Column(String, ForeignKey('registries.id'), nullable=False)
    malicious_package_id = Column(String, ForeignKey('malicious_packages.id'), nullable=False)
    
    # Blocking-specific metadata
    block_action = Column(String, nullable=False)  # e.g., 'blocked', 'quarantined', 'deleted'
    block_status = Column(String, nullable=False)  # e.g., 'success', 'failed', 'pending'
    blocked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan_result = relationship("ScanResultModel", back_populates="blocked_packages")
    registry = relationship("RegistryModel", back_populates="blocked_packages")
    malicious_package = relationship("MaliciousPackageModel", back_populates="blocked_packages")


class DatabaseStorage(StorageService):
    """Database storage provider using SQLAlchemy with SQLite.

    Extended to support:
    - Optional connection timeout (SQLite busy timeout)
    - Optional max connection 'pool size' semantics (no-op for SQLite but kept for parity)
    - In-memory database usage for tests (sqlite:///:memory:) retaining schema across sessions
    """
    
    def __init__(
        self,
        database_path: str = "data/security_scanner.db",
        default_registry_url: str = None,
        connection_timeout: float | int | None = None,
        max_connections: int | None = None,
        echo: bool = False,
        in_memory: bool | None = None,
    ):
        """Initialize database storage provider.

        Args:
            database_path: Path to SQLite database file or ':memory:'
            default_registry_url: Default registry URL if none specified
            connection_timeout: Busy timeout in seconds for SQLite (converted to milliseconds pragma)
            max_connections: Placeholder for future pool sizing (kept for API symmetry)
            echo: Enable SQL echo for debugging
            in_memory: Force in-memory mode (overrides database_path when True)
        """
        # Determine if using in-memory
        if in_memory or database_path == ":memory:":
            self.database_path = Path("/dev/null/" )  # dummy path for logging
            self.database_url = "sqlite+pysqlite:///:memory:"
            use_memory = True
        else:
            self.database_path = Path(database_path)
            # Ensure directory exists
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            self.database_url = f"sqlite+pysqlite:///{self.database_path}"
            use_memory = False

        self.default_registry_url = default_registry_url or "https://default-registry.example.com"
        self.connection_timeout = connection_timeout
        self.max_connections = max_connections
        self.echo = echo

        # Engine creation (StaticPool for in-memory to persist across sessions)
        engine_kwargs: Dict[str, Any] = {"echo": self.echo, "future": True}
        connect_args: Dict[str, Any] = {"check_same_thread": False}
        if self.connection_timeout is not None:
            # SQLite expects timeout in seconds via connect arg 'timeout'
            connect_args["timeout"] = float(self.connection_timeout)
        engine_kwargs["connect_args"] = connect_args

        if use_memory:
            from sqlalchemy.pool import StaticPool
            engine_kwargs["poolclass"] = StaticPool

        self.engine = create_engine(self.database_url, **engine_kwargs)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

        # Initialize schema & default registry
        self._initialize_database()
        self._ensure_default_registry()
        logger.debug(
            "Database storage initialized (memory=%s, path=%s, timeout=%s)",
            use_memory,
            database_path,
            self.connection_timeout,
        )
    
    def _ensure_default_registry(self) -> str:
        """Ensure default registry exists and return its ID."""
        with self.SessionLocal() as session:
            registry = session.query(RegistryModel).filter_by(base_url=self.default_registry_url).first()
            if not registry:
                registry = RegistryModel(
                    base_url=self.default_registry_url,
                    type="jfrog"
                )
                session.add(registry)
                session.commit()
                logger.debug(f"Created default registry: {self.default_registry_url}")
            return registry.id
    
    async def create_registry(self, url: str, registry_type: str, name: str = None, description: str = None) -> str:
        """
        Create a new registry.
        
        Args:
            url: Registry URL
            registry_type: Type of registry (e.g., 'jfrog', 'npm', 'pypi')
            name: Optional display name
            description: Optional description
            
        Returns:
            Registry ID
        """
        try:
            with self.SessionLocal() as session:
                # Check if registry already exists
                existing = session.query(RegistryModel).filter_by(base_url=url).first()
                if existing:
                    return existing.id
                
                registry = RegistryModel(
                    base_url=url,
                    type=registry_type
                )
                session.add(registry)
                session.commit()
                
                logger.debug(f"Created registry: {url} (ID: {registry.id})")
                return registry.id
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to create registry: {e}")
            raise StorageError(f"Failed to create registry: {e}") from e
    
    def _initialize_database(self) -> None:
        """Initialize database schema."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.debug("Database schema initialized successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to initialize database schema: {e}")
            raise StorageError(f"Failed to initialize database schema: {e}") from e
    
    async def store_scan_result(self, scan_result: ScanResult, registry_service: 'PackagesRegistryService' = None) -> bool:
        """
        Store a scan result in the database.
        
        Args:
            scan_result: The scan result to store
            registry_service: The registry service used for the scan (optional)
            
        Returns:
            True if stored successfully, False otherwise
        """
        logger.debug(f"Storing scan result: {scan_result.scan_id}")
        
        try:
            with self.SessionLocal() as session:
                # Get or create the registry based on the registry service
                if registry_service and hasattr(registry_service, 'base_url'):
                    # Try to find existing registry by base_url
                    registry = session.query(RegistryModel).filter_by(base_url=registry_service.base_url).first()
                    if not registry:
                        # Create new registry entry
                        registry = RegistryModel(
                            type='jfrog',  # Assume JFrog for now, could be made dynamic
                            base_url=registry_service.base_url
                        )
                        session.add(registry)
                        session.flush()
                else:
                    # Fallback to default registry
                    registry = session.query(RegistryModel).filter_by(type='default').first()
                    if not registry:
                        registry = RegistryModel(
                            type='default',
                            base_url='http://localhost'  # Default placeholder
                        )
                        session.add(registry)
                        session.flush()
                
                # Check if scan result already exists
                existing = session.query(ScanResultModel).filter_by(scan_id=scan_result.scan_id).first()
                
                if existing:
                    # Update existing record and clear related data
                    existing.timestamp = scan_result.timestamp
                    existing.status = scan_result.status.value
                    existing.packages_scanned = scan_result.packages_scanned
                    existing.errors = json.dumps(scan_result.errors)
                    existing.execution_duration_seconds = scan_result.execution_duration_seconds
                    
                    # Clear existing malicious packages and findings
                    session.query(MaliciousPackageModel).filter_by(scan_result_id=existing.id).delete()
                    session.query(FindingModel).filter_by(scan_result_id=existing.id).delete()
                    session.query(BlockedPackageModel).filter_by(scan_result_id=existing.id).delete()
                    
                    scan_result_model = existing
                    logger.debug(f"Updated existing scan result: {scan_result.scan_id}")
                else:
                    # Create new record
                    scan_result_model = ScanResultModel(
                        scan_id=scan_result.scan_id,
                        registry_id=registry.id,
                        timestamp=scan_result.timestamp,
                        status=scan_result.status.value,
                        packages_scanned=scan_result.packages_scanned,
                        errors=json.dumps(scan_result.errors),
                        execution_duration_seconds=scan_result.execution_duration_seconds
                    )
                    session.add(scan_result_model)
                    session.flush()  # Get the ID for relationships
                    
                    logger.debug(f"Created new scan result: {scan_result.scan_id}")
                
                # Store malicious packages found
                malicious_package_map = {}  # Track created packages for findings
                for package in scan_result.malicious_packages_found:
                    malicious_package_model = MaliciousPackageModel(
                        scan_result_id=scan_result_model.id,
                        name=package.name,
                        version=package.version,
                        ecosystem=package.ecosystem,
                        package_url=package.package_url,
                        advisory_id=package.advisory_id,
                        summary=package.summary,
                        details=package.details,
                        aliases=json.dumps(package.aliases),
                        affected_versions=json.dumps(package.affected_versions),
                        database_specific=json.dumps(package.database_specific),
                        published_at=package.published_at,
                        modified_at=package.modified_at
                    )
                    session.add(malicious_package_model)
                    session.flush()  # Get the ID
                    malicious_package_map[package.package_identifier] = malicious_package_model.id
                
                # Store findings (packages from malicious_packages_list)
                for package in scan_result.malicious_packages_list:
                    # Try to find matching malicious package or create one
                    malicious_package_id = malicious_package_map.get(package.package_identifier)
                    
                    if not malicious_package_id:
                        # Create a malicious package entry for this finding
                        malicious_package_model = MaliciousPackageModel(
                            scan_result_id=scan_result_model.id,
                            name=package.name,
                            version=package.version,
                            ecosystem=package.ecosystem,
                            package_url=package.package_url,
                            advisory_id=package.advisory_id,
                            summary=package.summary,
                            details=package.details,
                            aliases=json.dumps(package.aliases),
                            affected_versions=json.dumps(package.affected_versions),
                            database_specific=json.dumps(package.database_specific),
                            published_at=package.published_at,
                            modified_at=package.modified_at
                        )
                        session.add(malicious_package_model)
                        session.flush()  # Get the ID
                        malicious_package_id = malicious_package_model.id
                    
                    # Create the finding
                    finding_model = FindingModel(
                        scan_result_id=scan_result_model.id,
                        malicious_package_id=malicious_package_id
                    )
                    session.add(finding_model)
                
                # Store blocked packages using the relationship
                for blocked_package_name in scan_result.packages_blocked:
                    # Find the corresponding malicious package
                    malicious_package_id = None
                    for package_id, mp_id in malicious_package_map.items():
                        if blocked_package_name in package_id:  # Simple name matching
                            malicious_package_id = mp_id
                            break
                    
                    if malicious_package_id:
                        blocked_package_model = BlockedPackageModel(
                            scan_result_id=scan_result_model.id,
                            registry_id=registry.id,
                            malicious_package_id=malicious_package_id,
                            block_action='blocked',
                            block_status='success'
                        )
                        session.add(blocked_package_model)
                
                session.commit()
                return True
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to store scan result: {e}")
            raise StorageError(f"Failed to store scan result: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error storing scan result: {e}")
            raise StorageError(f"Unexpected error storing scan result: {e}") from e
    
    async def get_scan_results(
        self, 
        limit: Optional[int] = None,
        scan_id: Optional[str] = None
    ) -> List[ScanResult]:
        """
        Retrieve scan results from the database.
        
        Args:
            limit: Maximum number of results to return
            scan_id: Specific scan ID to retrieve
            
        Returns:
            List of scan results
        """
        logger.debug(f"Retrieving scan results (limit={limit}, scan_id={scan_id})")
        
        try:
            with self.SessionLocal() as session:
                query = session.query(ScanResultModel)
                
                if scan_id:
                    query = query.filter_by(scan_id=scan_id)
                
                # Order by timestamp descending (newest first)
                query = query.order_by(ScanResultModel.timestamp.desc())
                
                if limit:
                    query = query.limit(limit)
                
                results = query.all()
                
                # Group results by scan_id since we can have multiple rows per scan
                scan_results_dict = {}
                
                for result in results:
                    try:
                        if result.scan_id not in scan_results_dict:
                            # Get blocked package names for this scan
                            blocked_packages = session.query(BlockedPackageModel).join(
                                MaliciousPackageModel, BlockedPackageModel.malicious_package_id == MaliciousPackageModel.id
                            ).filter(
                                BlockedPackageModel.scan_result_id == result.id
                            ).all()
                            
                            blocked_package_names = [bp.malicious_package.name for bp in blocked_packages]
                            
                            # Create the base scan result
                            scan_results_dict[result.scan_id] = ScanResult(
                                scan_id=result.scan_id,
                                timestamp=result.timestamp,
                                status=ScanStatus(result.status),
                                packages_scanned=result.packages_scanned,
                                malicious_packages_found=[],
                                packages_blocked=blocked_package_names,
                                malicious_packages_list=[],
                                errors=json.loads(result.errors or "[]"),
                                execution_duration_seconds=result.execution_duration_seconds
                            )
                        
                        # Add malicious packages
                        for mp_model in result.malicious_packages:
                            malicious_package = self._malicious_package_model_to_entity(mp_model)
                            scan_results_dict[result.scan_id].malicious_packages_found.append(malicious_package)
                        
                        # Add findings to malicious_packages_list
                        for finding_model in result.findings:
                            finding_package = self._finding_model_to_malicious_package(finding_model)
                            scan_results_dict[result.scan_id].malicious_packages_list.append(finding_package)
                            
                    except Exception as e:
                        logger.warning(f"Failed to parse scan result {result.scan_id}: {e}")
                        continue
                
                scan_results = list(scan_results_dict.values())
                logger.debug(f"Retrieved {len(scan_results)} scan results")
                return scan_results
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            raise StorageError(f"Failed to retrieve scan results: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving scan results: {e}")
            raise StorageError(f"Unexpected error retrieving scan results: {e}") from e
    
    async def get_known_malicious_packages(self) -> List[MaliciousPackage]:
        """
        Get list of previously identified malicious packages from all scan results.
        
        Returns:
            List of known malicious packages
        """
        logger.debug("Retrieving known malicious packages from database")
        
        try:
            with self.SessionLocal() as session:
                # Get unique malicious packages from both tables
                unique_packages = {}
                
                # Get from malicious_packages table
                malicious_packages = session.query(MaliciousPackageModel).all()
                for mp_model in malicious_packages:
                    package = self._malicious_package_model_to_entity(mp_model)
                    unique_packages[package.package_identifier] = package
                
                # Get from findings table
                findings = session.query(FindingModel).all()
                for finding_model in findings:
                    package = self._finding_model_to_malicious_package(finding_model)
                    unique_packages[package.package_identifier] = package
                
                packages = list(unique_packages.values())
                logger.debug(f"Retrieved {len(packages)} known malicious packages")
                return packages
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to retrieve known malicious packages: {e}")
            raise StorageError(f"Failed to retrieve known malicious packages: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error retrieving known malicious packages: {e}")
            raise StorageError(f"Unexpected error retrieving known malicious packages: {e}") from e
    
    async def store_malicious_packages(self, packages: List[MaliciousPackage]) -> bool:
        """
        Store malicious packages (not implemented for database storage).
        
        Malicious packages are automatically stored as part of scan results.
        This method exists for interface compatibility.
        
        Args:
            packages: List of malicious packages to store
            
        Returns:
            True (packages are stored in scan results)
        """
        logger.debug(f"Malicious packages are stored as part of scan results, nothing to do for {len(packages)} packages")
        return True
    
    async def get_scan_summary(self, limit: Optional[int] = None) -> List[dict]:
        """
        Get scan summaries with basic metadata.
        
        This method is not implemented yet - use get_scan_results() instead.
        
        Args:
            limit: Maximum number of scan summaries to return
            
        Raises:
            NotImplementedError: Method not yet implemented
        """
        raise NotImplementedError(
            "get_scan_summary() is not yet implemented. Use get_scan_results() instead."
        )
    
    async def health_check(self) -> bool:
        """
        Check if database is accessible and can perform basic operations.
        
        Returns:
            True if service is healthy, False otherwise
        """
        try:
            with self.SessionLocal() as session:
                # Test basic database connectivity
                session.execute(text("SELECT 1"))
                session.commit()
                return True
                
        except Exception:
            return False
    
    def _malicious_package_model_to_entity(self, model: MaliciousPackageModel) -> MaliciousPackage:
        """Convert MaliciousPackageModel to MaliciousPackage entity."""
        return MaliciousPackage(
            name=model.name,
            version=model.version,
            ecosystem=model.ecosystem,
            package_url=model.package_url,
            advisory_id=model.advisory_id,
            summary=model.summary,
            details=model.details,
            aliases=json.loads(model.aliases or "[]"),
            affected_versions=json.loads(model.affected_versions or "[]"),
            database_specific=json.loads(model.database_specific or "{}"),
            published_at=model.published_at,
            modified_at=model.modified_at
        )
    
    def _finding_model_to_malicious_package(self, model: FindingModel) -> MaliciousPackage:
        """Convert FindingModel to MaliciousPackage entity for malicious_packages_list."""
        # Get the malicious package data through the relationship
        mp = model.malicious_package
        return MaliciousPackage(
            name=mp.name,
            version=mp.version,
            ecosystem=mp.ecosystem,
            package_url=mp.package_url,
            advisory_id=mp.advisory_id,
            summary=mp.summary,
            details=mp.details,
            aliases=json.loads(mp.aliases or "[]"),
            affected_versions=json.loads(mp.affected_versions or "[]"),
            database_specific=json.loads(mp.database_specific or "{}"),
            published_at=mp.published_at,
            modified_at=mp.modified_at
        )