# Coding Standards and Development Guidelines

This document outlines the coding standards, development practices, and guidelines for the Security Scanner project.

## 🎯 Project Philosophy

### Clean Architecture Principles

This project strictly follows Clean Architecture patterns to ensure:

- **Dependency Inversion**: High-level modules don't depend on low-level modules
- **Single Responsibility**: Each class/module has one reason to change
- **Interface Segregation**: No client should depend on methods it doesn't use
- **Open/Closed Principle**: Open for extension, closed for modification

### Core Tenets

1. **Testability First**: All code must be unit testable
2. **Provider Interchangeability**: External services must be swappable
3. **Configuration Driven**: Behavior controlled via configuration, not code
4. **Graceful Degradation**: Failures in non-critical services shouldn't stop the application
5. **Security by Design**: Secure defaults, input validation, credential protection

## 📋 Code Standards

### Python Style Guide

We follow PEP 8 with these specific guidelines:

#### Imports

```python
# Standard library first
import asyncio
import logging
from typing import Dict, List, Optional

# Third-party libraries
import aiohttp
from pydantic import BaseModel

# Local imports last
from src.core.entities.malicious_package import MaliciousPackage
from src.core.interfaces.packages_feed import PackagesFeed
```

#### Class Design

```python
class ServiceImplementation(AbstractInterface):
    """Concrete implementation of service interface.
    
    Args:
        config: Configuration object
        logger: Logger instance
    """
    
    def __init__(self, config: Config, logger: logging.Logger):
        self._config = config
        self._logger = logger
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
```

#### Error Handling

```python
async def risky_operation(self) -> Result:
    """Perform operation that might fail.
    
    Returns:
        Result object with success/failure status
        
    Raises:
        ServiceUnavailableError: When external service is down
    """
    try:
        response = await self._make_request()
        return Result(success=True, data=response)
    except aiohttp.ClientError as e:
        self._logger.error(f"Network error: {e}")
        return Result(success=False, error=str(e))
    except Exception as e:
        self._logger.exception("Unexpected error in risky_operation")
        raise ServiceUnavailableError(f"Operation failed: {e}")
```

### Type Annotations

- **Required**: All function signatures must have type hints
- **Optional Types**: Use `Optional[T]` for nullable values
- **Collections**: Use specific types like `List[str]`, `Dict[str, int]`
- **Return Types**: Always specify return types, use `None` for procedures

```python
async def fetch_packages(self, limit: Optional[int] = None) -> List[MaliciousPackage]:
    """Fetch malicious packages from feed."""
    packages: List[MaliciousPackage] = []
    # Implementation...
    return packages
```

### Documentation Standards

#### Docstrings

Use Google-style docstrings:

```python
def complex_function(param1: str, param2: int, param3: Optional[bool] = None) -> Dict[str, Any]:
    """Brief description of function purpose.
    
    Longer description if needed. Explain the business logic,
    any side effects, or important implementation details.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter  
        param3: Optional parameter description. Defaults to None.
        
    Returns:
        Dictionary containing result data with keys:
        - 'status': Operation status string
        - 'data': Processed data object
        
    Raises:
        ValueError: When param1 is empty
        ServiceError: When external service fails
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result['status'])
        'success'
    """
```

#### Comments

```python
# Business logic explanation
if package.ecosystem == "npm" and package.name.startswith("@"):
    # Scoped npm packages require special handling for JFrog API
    registry_path = f"npm/{package.name.replace('@', '%40')}"
else:
    registry_path = f"{package.ecosystem}/{package.name}"

# TODO: Add support for Maven coordinate transformation
# See: https://github.com/company/security-scanner/issues/123
```

## 🏗️ Architecture Patterns

### Dependency Injection

All external dependencies must be injected, never instantiated directly:

```python
# ❌ Wrong - Direct instantiation
class SecurityScanner:
    def __init__(self):
        self.feed = OSVFeed()  # Hard dependency
        
# ✅ Correct - Dependency injection
class SecurityScanner:
    def __init__(self, 
                 feed: PackagesFeed, 
                 registry: PackagesRegistryService):
        self._feed = feed
        self._registry = registry
```

### Interface Design

Interfaces should be minimal and focused:

```python
from abc import ABC, abstractmethod

class PackagesFeed(ABC):
    """Abstract interface for malicious package feeds."""
    
    @abstractmethod
    async def fetch_malicious_packages(self) -> List[MaliciousPackage]:
        """Fetch current malicious packages."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if feed service is available."""
        pass
```

### Factory Pattern

Use factories for complex object creation:

```python
class ServiceFactory:
    """Factory for creating service instances."""
    
    @staticmethod
    async def create_packages_feed(config: Config) -> PackagesFeed:
        """Create packages feed based on configuration."""
        feed_type = config.packages_feed.type
        
        if feed_type == "osv":
            return OSVFeed(config.packages_feed, logging.getLogger("OSVFeed"))
        elif feed_type == "custom":
            return CustomFeed(config.packages_feed, logging.getLogger("CustomFeed"))
        else:
            raise ValueError(f"Unknown feed type: {feed_type}")
```

## 🧪 Testing Standards

### Test Structure

We use a **co-located test structure** where test files are placed directly next to their corresponding source files using the `_test.py` suffix:

```
src/
├── config/
│   ├── config_loader.py
│   └── config_test.py          # Tests for config_loader.py
├── core/
│   ├── entities/
│   │   ├── malicious_package.py
│   │   ├── scan_result.py
│   │   └── entities_test.py    # Tests for all entity classes
│   └── usecases/
│       ├── security_scanner.py
│       ├── security_scanner_test.py  # Tests for SecurityScanner
│       ├── data_management.py
│       └── data_management_test.py   # Tests for DataManagementUseCase
└── providers/
    ├── feeds/
    │   ├── osv_feed.py
    │   └── osv_feed_test.py      # Tests for OSV feed implementation
    └── registries/
        ├── jfrog_registry.py
        └── jfrog_registry_test.py # Tests for JFrog registry

tests/
├── integration/            # Integration tests with external dependencies
│   ├── test_jfrog_integration.py
│   └── test_complete_scan.py
└── fixtures/              # Shared test data and utilities
    ├── osv_response.json
    └── mock_servers.py

conftest.py                 # Global test configuration and fixtures
```

### Test Organization Benefits

- **Discoverability**: Tests are easy to find next to their source code
- **Maintainability**: Changes to source code immediately highlight related tests
- **Locality**: Reduces cognitive load when working on a specific module
- **Import Simplicity**: Test files can use relative imports or short absolute paths

### Co-located Test Conventions

#### File Naming
- Test files must use the `_test.py` suffix (e.g., `security_scanner_test.py`)
- Test files should be placed in the same directory as the source file they test
- For modules with multiple classes, group related tests in one `*_test.py` file

#### Import Guidelines
Use absolute imports from the project root for consistency:

```python
# ✅ Preferred: Absolute imports
from src.core.usecases.security_scanner import SecurityScanner
from src.core.entities import MaliciousPackage, ScanResult

# ✅ Alternative: Relative imports for same directory
from .security_scanner import SecurityScanner

# ❌ Avoid: Mixed import styles within same file
```

#### Test Discovery
- `conftest.py` should be placed at the project root for global fixtures
- Module-specific fixtures can be defined within each test file
- Use `pytest src/` to run all co-located tests
- Use `pytest src/path/to/specific_test.py` for individual test files

### Unit Test Guidelines

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime

# Co-located test imports
from src.core.usecases.security_scanner import SecurityScanner
from src.core.entities import MaliciousPackage, ScanResult, ScanStatus

class TestSecurityScanner:
    """Test suite for SecurityScanner use case."""
    
    @pytest.fixture
    def mock_packages_feed(self):
        """Mock packages feed service."""
        mock = AsyncMock()
        mock.fetch_malicious_packages.return_value = []
        mock.health_check.return_value = True
        return mock
    
    @pytest.fixture
    def security_scanner(self, mock_packages_feed, mock_packages_registry, 
                        mock_notification_service, mock_storage_service):
        """Create security scanner with mocked dependencies."""
        return SecurityScanner(
            packages_feed=mock_packages_feed,
            registry_service=mock_packages_registry,
            notification_service=mock_notification_service,
            storage_service=mock_storage_service
        )
    
    @pytest.mark.asyncio
    async def test_execute_scan_success_no_new_packages(self, security_scanner, 
                                                        mock_packages_feed,
                                                        mock_packages_registry,
                                                        mock_storage_service,
                                                        sample_malicious_package):
        """Test successful scan with no new packages."""
        # Arrange
        mock_packages_feed.fetch_malicious_packages.return_value = [sample_malicious_package]
        mock_packages_registry.check_existing_packages.return_value = [sample_malicious_package]
        mock_packages_registry.block_packages.return_value = []
        
        # Act
        result = await security_scanner.execute_scan()
        
        # Assert
        assert result.status == ScanStatus.SUCCESS
        assert result.packages_scanned == 1
        assert len(result.malicious_packages_found) == 1
        assert len(result.packages_blocked) == 0
        assert result.is_successful
        mock_packages_feed.fetch_malicious_packages.assert_called_once()
        mock_storage_service.store_scan_result.assert_called_once()
```

### Integration Test Guidelines

**Integration tests are MANDATORY for every provider and must be created as part of the provider development process.**

#### Integration Test Architecture Levels

Integration tests should be implemented at multiple levels to ensure comprehensive coverage:

##### **Level 1: Provider Integration Tests**
Test individual providers directly against real external APIs:

```python
@pytest.mark.integration
class TestJFrogProviderIntegration:
    """Test JFrog provider directly against real API."""
    
    @pytest_asyncio.fixture
    async def jfrog_provider(self, config):
        """Create provider directly with configuration."""
        provider = JFrogRegistry(
            base_url=config.jfrog_base_url,
            api_key=config.jfrog_api_key
        )
        async with provider:
            yield provider
    
    async def test_api_contract_compliance(self, jfrog_provider):
        """Verify provider correctly implements external API contract."""
        # Test real API communication, data transformation, error handling
```

**Purpose**: 
- Validate provider implementation against real external services
- Test API contract compliance and data transformation
- Isolate provider-specific issues for faster debugging

##### **Level 2: Factory Integration Tests**
Test the complete dependency injection and factory creation flow:

```python
@pytest.mark.integration
class TestRegistryFactoryIntegration:
    """Test complete registry creation via dependency injection."""
    
    async def test_provider_creation_via_factory(self, config):
        """Test full Config → Factory → Provider → API flow."""
        registry_factory = RegistryFactory(config)
        registry = await registry_factory.create_registry("jfrog")
        
        # Test that factory-created provider works correctly
        result = await registry.search_packages("axios", "npm")
        assert isinstance(result, list)
```

**Purpose**:
- Validate dependency injection setup
- Test configuration loading and provider creation
- Ensure factory pattern works correctly with real services

##### **Level 3: Use Case Integration Tests**
Test complete application workflows with real providers:

```python
@pytest.mark.integration
class TestSecurityScannerIntegration:
    """Test complete security scanning workflow."""
    
    async def test_end_to_end_scan_with_real_providers(self, config):
        """Test complete scan workflow with real JFrog and OSV."""
        # Create scanner with real providers via DI
        scanner = await SecurityScannerFactory.create(config)
        
        # Test complete workflow
        scan_result = await scanner.execute_scan()
        assert scan_result.is_successful
```

**Purpose**:
- Test complete application functionality
- Validate cross-component integration
- Ensure the full clean architecture flow works end-to-end

#### Integration Test Selection Guidelines

**For Provider Development**: Start with Level 1 (Provider Integration)
**For Feature Development**: Use Level 2 (Factory Integration) 
**For Release Validation**: Include Level 3 (Use Case Integration)
**For CI/CD Pipelines**: Use Level 1 only (faster, more focused)

#### Integration Test Requirements

All integration test levels must include:
- **Real API Testing**: No mocking of external services
- **Configuration Compliance**: Use same .env variables as production
- **Error Scenario Coverage**: Test both success and failure cases
- **CI Exclusion**: Use `@pytest.mark.integration` marker
- **Environment Skipping**: Honor `SKIP_INTEGRATION_TESTS` variable

#### Integration Test Structure

Integration tests are organized in the `tests/integration/` directory:

```
tests/
├── integration/
│   ├── test_jfrog_integration.py      # JFrog Artifactory provider tests
│   ├── test_osv_integration.py        # OSV Feed provider tests
│   ├── test_cli_integration.py        # CLI functionality tests
│   └── test_scanner_integration.py    # End-to-end scanner tests
└── fixtures/
    ├── integration_config.yaml        # Test configuration
    └── test_data.json                 # Shared test data
```

#### Integration Test Markers

All integration tests must use the `@pytest.mark.integration` marker:

```python
@pytest.mark.integration
class TestJFrogIntegration:
    """Integration tests for JFrog Artifactory provider."""
    
    @pytest.fixture(scope="class")
    def config(self):
        """Load integration test configuration."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")
        
        config_loader = ConfigLoader()
        config = config_loader.load()
        
        if not config.jfrog_base_url:
            pytest.skip("JFrog configuration not available")
            
        return config
```

#### Provider-Specific Test Requirements

##### JFrog Registry Integration Tests

Must include tests for:
- Health check functionality
- Package search with existing packages (e.g., "axios")
- Package search with non-existing packages (e.g., "thispackagedoesntexist")
- Bulk operations and performance testing
- Error handling and timeout scenarios
- Concurrent operation handling

```python
@pytest.mark.asyncio
async def test_search_existing_package(self, jfrog_registry):
    """Test searching for a package that exists (axios)."""
    results = await jfrog_registry.search_package("axios")
    assert len(results) > 0, "axios package should exist"
    assert any("axios" in result.name.lower() for result in results)

@pytest.mark.asyncio
async def test_search_nonexistent_package(self, jfrog_registry):
    """Test searching for a package that doesn't exist."""
    results = await jfrog_registry.search_package("thispackagedoesntexist")
    assert len(results) == 0, "Non-existent package should return empty results"
```

##### OSV Feed Integration Tests

Must include tests for:
- Health check functionality
- NPM vulnerability log retrieval (REQUIRED)
- Package-specific vulnerability queries
- Bulk package queries
- Error handling for invalid requests
- Comprehensive logging of npm data

```python
@pytest.mark.asyncio
async def test_fetch_npm_logs(self, osv_feed):
    """Test fetching npm vulnerability logs - REQUIRED."""
    malicious_packages = await osv_feed.fetch_malicious_packages(max_packages=10)
    npm_packages = [pkg for pkg in malicious_packages if pkg.ecosystem == "npm"]
    
    # Log the results as required
    logging.info(f"OSV Feed Integration Test - NPM Logs:")
    logging.info(f"Found {len(npm_packages)} npm malicious packages")
    
    for i, pkg in enumerate(npm_packages[:3], 1):
        logging.info(f"NPM Package {i}: {pkg.name} (ID: {pkg.id})")
```

##### CLI Integration Tests

Must include tests for:
- All CLI command functionality
- Help and version commands
- Package scanning workflows
- Error handling for invalid inputs
- Configuration file handling
- Output format validation

```python
def test_cli_package_scanning(self, cli_path):
    """Test CLI package scanning with known packages."""
    # Test with existing package
    returncode, stdout, stderr = self.run_cli_command(cli_path, ["scan", "axios"])
    # Validate output...
    
    # Test with non-existing package  
    returncode, stdout, stderr = self.run_cli_command(cli_path, ["scan", "thispackagedoesntexist"])
    # Validate error handling...
```

#### Integration Test Configuration

Integration tests require special configuration management:

```python
# Environment variable to skip integration tests
SKIP_INTEGRATION_TESTS=true pytest tests/

# Run only integration tests
pytest -m integration tests/integration/

# Exclude integration tests (default for CI)
pytest -m "not integration" tests/
```

#### CI/CD Integration Test Exclusion

Integration tests must be excluded from CI pipelines using pytest markers:

```yaml
# In pytest.ini or pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: marks tests as integration tests (deselect with '-m \"not integration\"')",
    "slow: marks tests as slow (deselect with '-m \"not slow\"')"
]

# CI configuration should use:
# pytest -m "not integration" tests/
```

#### Integration Test Documentation

Each integration test must include:
- Clear docstrings explaining the test purpose
- Logging statements for debugging and verification
- Skip conditions for missing configuration
- Comprehensive error messages

Example integration test template:

```python
"""Integration tests for [Provider Name]."""

import pytest
import os
import logging
from src.config import ConfigLoader
from src.providers.[category].[provider] import [ProviderClass]

@pytest.mark.integration
class Test[Provider]Integration:
    """Integration tests for [Provider] functionality.
    
    These tests require actual [Provider] credentials and should not run in CI.
    Set SKIP_INTEGRATION_TESTS=true to skip these tests.
    """
    
    @pytest.fixture(scope="class")
    def config(self):
        """Load configuration for integration tests."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")
        
        config_loader = ConfigLoader()
        config = config_loader.load()
        
        # Verify required configuration
        if not config.[required_config]:
            pytest.skip("[Provider] configuration not available")
            
        return config
    
    @pytest.fixture
    async def provider_instance(self, config):
        """Create provider instance."""
        provider = [ProviderClass](
            # Configuration parameters...
        )
        
        async with provider:
            yield provider
    
    @pytest.mark.asyncio
    async def test_health_check(self, provider_instance):
        """Test provider health check."""
        is_healthy = await provider_instance.health_check()
        assert is_healthy, "[Provider] should be healthy"
        logging.info("✓ [Provider] health check passed")
    
    # Additional test methods...
```

### Test Coverage Requirements

- **Minimum**: 90% line coverage
- **Branches**: 85% branch coverage
- **Critical Paths**: 100% coverage for security-related code
- **Integration**: All external service integrations must have integration tests

## 🔧 Development Workflow

### Git Workflow

1. **Feature Branches**: Create branches from `main` for all changes
2. **Naming**: Use descriptive names like `feature/add-maven-support`
3. **Commits**: Write clear, atomic commits with descriptive messages
4. **Pull Requests**: All changes must go through PR review

#### Commit Message Format

```
type(scope): brief description

Detailed explanation of changes, motivation, and impact.
Include references to issues or tickets.

Fixes #123
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

### Code Review Guidelines

#### For Authors

- **Self-Review**: Review your own PR first
- **Small PRs**: Keep changes focused and reviewable
- **Tests**: Include tests for all new functionality
- **Documentation**: Update docs for API changes

#### For Reviewers

- **Functionality**: Does the code solve the problem correctly?
- **Design**: Does it follow Clean Architecture principles?
- **Security**: Are there any security vulnerabilities?
- **Performance**: Any performance implications?
- **Tests**: Are tests comprehensive and meaningful?

### Release Process

1. **Version Bumping**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Changelog**: Update CHANGELOG.md with release notes
3. **Testing**: Run full test suite including integration tests
4. **Deployment**: Test in staging before production release

## 🤖 AI Assistant Guidelines

When AI assistants contribute to this project, they must follow these specific guidelines:

### Code Modification Rules

1. **Architecture Preservation**: Never violate Clean Architecture boundaries
2. **Interface Stability**: Don't change existing interfaces without migration plan
3. **Test Coverage**: Add tests for all new code, update existing tests for changes
4. **Configuration**: New features must be configurable, not hard-coded

### AI-Specific Standards

```python
# ✅ AI should create code like this
class NewFeature:
    """AI-generated feature following project standards.
    
    This class implements X functionality while maintaining
    clean architecture principles and full test coverage.
    """
    
    def __init__(self, dependency: AbstractInterface):
        self._dependency = dependency
        
    async def process(self, input_data: InputType) -> OutputType:
        """Process input according to business rules."""
        # Clear, well-documented implementation
        pass

# ❌ AI should NOT create code like this
def quick_fix():
    # Hard-coded values, no error handling
    return requests.get("http://hardcoded-url").json()
```

### AI Code Review Checklist

Before submitting AI-generated code, verify:

- [ ] Follows existing patterns and conventions
- [ ] Includes comprehensive type hints
- [ ] Has proper error handling
- [ ] Includes unit tests
- [ ] Updates integration tests if needed
- [ ] Documents any new configuration options
- [ ] Follows security best practices
- [ ] Maintains backward compatibility

### Prohibited AI Actions

❌ **Never do these things:**

- Modify core entity interfaces without discussion
- Add direct dependencies between layers
- Hard-code credentials or URLs
- Skip error handling for external services
- Create untested code
- Break existing tests without fixing them
- Ignore type checking errors
- Use deprecated patterns or libraries

### AI Enhancement Guidelines

✅ **AI assistants should:**

- Suggest improvements to existing code
- Add comprehensive tests for edge cases
- Enhance error messages and logging
- Optimize performance while maintaining readability
- Add configuration options for hard-coded values
- Improve documentation and examples
- Identify and fix security vulnerabilities

## 📊 Quality Metrics

### Code Quality Gates

All code must pass these quality checks:

```bash
# Type checking
mypy src/

# Linting
flake8 src/
black --check src/

# Security scanning
bandit -r src/

# Test coverage
pytest --cov=src --cov-fail-under=90

# Integration tests
pytest tests/integration/
```

### Performance Standards

- **Startup Time**: < 5 seconds for application initialization
- **Scan Duration**: < 2 minutes for typical scan (1000 packages)
- **Memory Usage**: < 256MB peak memory during scan
- **API Response**: < 5 seconds for health check endpoints

### Security Standards

- **No Hardcoded Secrets**: All credentials via environment variables
- **Input Validation**: Validate all external input
- **SQL Injection**: Use parameterized queries only
- **XSS Prevention**: Escape all user-provided content
- **Dependency Scanning**: Regular security audits of dependencies

### Database Standards

#### Primary Keys
- **UUID Required**: All table primary keys must use UUID (version 4) by default
- **No Auto-increment**: Avoid sequential integers for primary keys
- **Consistent Naming**: All primary key columns must be named `id`

```python
# ✅ Correct - UUID primary keys
from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
import uuid

class RegistryModel(Base):
    __tablename__ = 'registries'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
```

#### Foreign Keys
- **UUID References**: All foreign keys must reference UUID primary keys
- **Naming Convention**: Foreign key columns use `{table_name}_id` format
- **Cascading**: Define appropriate cascade behaviors for data integrity

```python
# ✅ Correct - UUID foreign keys with proper naming
class ScanResultModel(Base):
    __tablename__ = 'scan_results'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    registry_id = Column(String(36), ForeignKey('registries.id', ondelete='CASCADE'), nullable=False)
```

#### Schema Design Principles
- **Normalization**: Use normalized tables, avoid JSON blob storage
- **Audit Fields**: Include `created_at` and `updated_at` timestamps on all tables
- **Soft Deletes**: Use `deleted_at` timestamp instead of hard deletes for important data
- **Indexes**: Create indexes on frequently queried foreign key columns

```python
# ✅ Complete table example with all standards
class MaliciousPackageModel(Base):
    __tablename__ = 'malicious_packages'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String(36), ForeignKey('scan_results.id', ondelete='CASCADE'), nullable=False)
    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False, index=True)
    
    # Audit fields (required)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)  # Soft delete
    
    # Relationships
    scan_result = relationship("ScanResultModel", back_populates="malicious_packages")
```

#### Migration Standards
- **Reversible**: All migrations must be reversible with proper down methods
- **Data Safety**: Never drop columns with data without backup strategy
- **Performance**: Consider impact on large tables, use background migrations when needed

## 🛡️ Security Considerations

### Credential Management

```python
# ✅ Correct way to handle credentials
class JFrogRegistry:
    def __init__(self, config: JFrogConfig):
        self._api_key = config.api_key  # From environment
        self._base_url = config.base_url
        
    async def _make_authenticated_request(self, endpoint: str):
        headers = {"X-JFrog-Art-Api": self._api_key}
        # Never log headers containing credentials
        self._logger.debug(f"Making request to {endpoint}")

# ❌ Wrong way
def get_packages():
    api_key = "AKCp5..." # Hard-coded credential
    response = requests.get(f"https://company.jfrog.io/api/packages", 
                          headers={"Authorization": f"Bearer {api_key}"})
```

### Input Validation

```python
def validate_package_name(name: str) -> bool:
    """Validate package name to prevent injection attacks."""
    if not name or len(name) > 255:
        return False
    
    # Only allow alphanumeric, hyphens, dots, underscores
    import re
    pattern = r'^[a-zA-Z0-9._-]+$'
    return bool(re.match(pattern, name))
```

## 📚 Learning Resources

### Recommended Reading

- Clean Architecture by Robert Martin
- Python Tricks by Dan Bader
- Effective Python by Brett Slatkin
- Architecture Patterns with Python by Harry Percival

### Project-Specific Resources

- [OSV API Documentation](https://osv.dev/docs/)
- [JFrog Artifactory REST API](https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API)
- [asyncio Best Practices](https://docs.python.org/3/library/asyncio.html)

---

## 📝 Document Maintenance

This document should be updated when:

- New architectural patterns are introduced
- Coding standards change
- New tools or frameworks are adopted
- Security requirements evolve
- AI assistant capabilities expand

**Last Updated**: December 2023  
**Next Review**: March 2024