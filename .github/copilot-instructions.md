# Copilot Instructions for Malifiscan Security Scanner

## 🏗️ Architecture Overview
- Follows Clean Architecture: business logic in `src/core`, external providers in `src/providers`, configuration in `src/config`, dependency injection in `src/factories`.
- Key entities: `MaliciousPackage`, `ScanResult`, `NotificationEvent` (see `src/core/entities/`).
- Service interfaces in `src/core/interfaces/` (e.g., `PackagesFeed`, `PackagesRegistryService`, `NotificationService`, `StorageService`).
- Providers implement interfaces in `src/providers/feeds`, `src/providers/registries`, etc.
- All dependencies are injected via factories (`src/factories/service_factory.py`).
- Configuration is driven by `config.yaml` and `.env` files.

## ⚙️ Developer Workflow
- Use [UV](https://github.com/astral-sh/uv) for dependency management and running commands (recommended):
  - `uv sync --dev` to install all dependencies
  - `uv run python cli.py health check` to verify setup
  - `uv run pytest tests/unit/` for unit tests (fast feedback loop)
  - `uv run pytest tests/ -m integration` for integration tests
  - `uv run pytest tests/ -m "not integration"` for all unit tests
- Traditional pip/venv is supported; see `CONTRIBUTING.md` for details.
- Make CLI executable: `chmod +x cli.py`

## 🧪 Testing Conventions
- **Separated test structure**: Unit tests in `tests/unit/` with clean directory structure mirroring `src/`
- **Integration tests**: Located in `tests/integration/`, must use `@pytest.mark.integration`
- **Import pattern**: Use absolute imports from project root (`from src.module import Class`)
- Use real entities and avoid excessive mocking; prefer interface-based testing
- Coverage: Minimum 90% line coverage required (`pytest --cov=src --cov-fail-under=90`)
- **Centralized fixtures**: Use fixtures from `conftest.py` for consistency and maintainability
- **Configuration loading**: Use `test_config` fixture instead of repeating `ConfigLoader(config_file=test_config_path).load()`
- **Test data**: Use consolidated fixtures like `test_malicious_packages` with derived convenience fixtures

## 📦 Configuration & Storage
- Main config: `config.yaml` (controls provider types, storage, scheduler, etc.)
- Environment: `.env` for secrets and runtime settings (never commit credentials)
- Database: SQLite schema with UUID primary keys, normalized tables (see ERD in `CONTRIBUTING.md`)
- Switch storage type in `config.yaml` (`file` or `database`)

## 🛡️ Coding Standards
- Strict PEP 8 compliance, with absolute imports from project root
- All functions/classes require type hints and Google-style docstrings
- Dependency injection is mandatory; never instantiate providers directly
- Error handling: wrap external failures, log errors, never expose sensitive info
- Security: credentials via env, input validation, no hardcoded secrets

## 🚦 Quality Gates
- Type check: `mypy src/`
- Lint: `flake8 src/`, `black --check src/`
- Security scan: `bandit -r src/`
- Test coverage: `pytest --cov=src --cov-fail-under=90`

## 🧩 Extending the System
- To add a new provider/feed/registry/notification:
  1. Implement the relevant interface in `src/core/interfaces/`
  2. Add provider in `src/providers/[category]/`
  3. Register in `src/factories/service_factory.py`
  4. Update `config.yaml` schema
  5. Add unit test in `tests/unit/[category]/` and integration test in `tests/integration/`

## 🚫 Prohibited AI Actions
- Do NOT break Clean Architecture boundaries
- Do NOT hard-code credentials, URLs, or config
- Do NOT skip error handling or tests
- Do NOT modify core interfaces without migration plan
- Do NOT introduce direct dependencies between layers
- **Do NOT put business logic in CLI files** - CLI must only handle presentation and call use cases

## 🖥️ CLI Design Guidelines
**CRITICAL RULE: `cli.py` must NEVER contain business logic**

The CLI serves only as a presentation layer that:
- Parses command-line arguments and routes to handlers
- Displays formatted output and user interaction
- Calls appropriate use cases from `src/core/usecases/`
- Handles user prompts and confirmations

**CLI Pattern:**
```python
# ✅ Correct - CLI delegates to use case
async def config_validate(self) -> bool:
    # UI/presentation only
    self.console.print("🔍 Validating...", style="cyan")
    
    # Delegate to use case
    usecase = ConfigurationManagementUseCase(...)
    success, results = await usecase.validate_configuration()
    
    # Display results
    self._display_results(results)
    return success

# ❌ Wrong - Business logic in CLI
async def config_validate(self) -> bool:
    # Complex validation logic here - FORBIDDEN
    config = ConfigLoader(...).load()
    if config.registry.enabled and not config.jfrog_url:
        # ... business rules - MOVE TO USE CASE
```

**When adding CLI commands:**
1. Create or update appropriate use case in `src/core/usecases/`
2. CLI method should only parse args, call use case, display results
3. All file operations, validation, configuration logic goes in use case
4. Add unit tests for the use case in `tests/unit/core/`, integration tests in `tests/integration/`

## ✅ AI Enhancement Guidelines
- Prefer improving test coverage, error messages, logging, and configuration flexibility
- Suggest performance/security improvements with code and documentation
- Always update or add tests for new/changed code

## 📚 Key References
- See `STANDARDS.md` for coding/test standards
- See `CONTRIBUTING.md` for architecture, workflow, and database details
- See `src/core/interfaces/` and `src/factories/` for extension patterns
- See `tests/unit/` for unit test structure and `tests/integration/` for integration test structure

---
_Last updated: 2025-09-20_
## 📝 Documentation Structure & Guidelines

Project documentation is organized as follows:

- **README.md**: High-level overview, features, quick start, installation, usage examples, and troubleshooting. Update when user-facing features, CLI commands, or onboarding steps change.
- **CONTRIBUTING.md**: Developer setup, architecture, configuration, testing strategy, database schema, extension workflow, and contribution process. Update when workflows, architecture, or testing practices change.
- **STANDARDS.md**: Coding standards, Clean Architecture rules, test conventions, code review, security, and AI agent guidelines. Update when coding practices, review process, or quality gates change.

**When to document where:**
- New features or CLI commands: add to `README.md` (user-facing) and `CONTRIBUTING.md` (developer-facing)
- Changes to architecture, workflows, or test strategy: update `CONTRIBUTING.md`
- Coding style, error handling, or test requirements: update `STANDARDS.md`
- API changes: update all three as relevant (usage in `README.md`, implementation in `CONTRIBUTING.md`, standards in `STANDARDS.md`)

**Examples:**
- Adding a new provider: document extension steps in `CONTRIBUTING.md`, update usage in `README.md`, and add interface/coding rules in `STANDARDS.md`.
- Changing test coverage requirements: update `STANDARDS.md` and reference in `CONTRIBUTING.md`.

Always keep documentation up to date with code and workflows. Reference these files for guidance before making changes.
