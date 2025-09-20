# Malifiscan

A security tool that detects malicious packages from external vulnerability feeds and searches for them in your package registries or artifact repositories.

## 🛡️ Features

- **OSV Feed Integration**: Fetches malicious package data from Google Cloud Storage OSV vulnerability database
- **JFrog Artifactory Search**: Searches for packages in your Artifactory repositories using AQL (Artifactory Query Language)
- **Security Cross-Reference**: Compares OSV malicious packages against your JFrog repositories to identify potential threats
- **Package Blocking**: Block malicious packages using JFrog Artifactory exclusion patterns to prevent downloads
- **Package Management**: View, block, and unblock packages with enterprise-grade safety features
- **Time-Based Filtering**: Configurable time window for fetching recent malicious packages (default: 48 hours)
- **Rich CLI Interface**: Interactive command-line interface with progress bars and formatted output
- **Comprehensive Health Checks**: Validates connectivity to OSV and JFrog services

## 🚫 Package Blocking & Security

Malifiscan can automatically block malicious packages in your JFrog Artifactory repositories using **exclusion patterns**. This prevents developers from downloading compromised packages while preserving existing patterns.

### How Exclusion Patterns Work

When you block a package, Malifiscan:

1. **Generates specific patterns** for the malicious package (e.g., `axios/-/axios-1.12.2.tgz`)
2. **Updates repository configuration** by adding patterns to the `excludesPattern` field
3. **Preserves existing patterns** using safe union-based merging

### Blocking Commands

```bash
# Block a specific package version
uv run python cli.py registry block axios npm 1.12.2

# Block all versions of a package  
uv run python cli.py registry block malicious-pkg npm "*"

# View currently blocked packages
uv run python cli.py registry list-blocked npm

# Unblock a package
uv run python cli.py registry unblock axios npm 1.12.2
```

### Safety Features

- **Pattern Preservation**: Existing exclusion patterns are never overwritten
- **Granular Control**: Block specific versions or entire packages
- **Audit Trail**: All blocking operations are logged and traceable

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- JFrog Artifactory instance with API access
- Internet connectivity for OSV database access

### Installation

#### Option 1: Using UV (Recommended)

UV is a fast Python package manager that provides better dependency resolution and faster installs.

1. **Install UV** (if not already installed)

2. **Clone and setup the project**
   ```bash
   git clone <repository-url>
   cd malifiscan
   
   # Initialize UV project and install dependencies
   uv init --no-readme --no-pin-python
   uv sync --dev
   ```

3. **Initialize configuration**
   ```bash
   # Generate local configuration files from templates
   uv run python cli.py config init
   
   # Edit the generated files with your settings:
   # - .env: Add your JFrog credentials
   # - config.local.yaml: Customize any settings
   ```

4. **Verify setup**
   ```bash
   uv run python cli.py config validate
   uv run python cli.py health check
   ```

#### Option 2: Using pip (Traditional)

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd malifiscan
   
   # Create and activate virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Upgrade pip and install dependencies
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. **Initialize configuration**
   ```bash
   # Generate local configuration files from templates
   python cli.py config init
   
   # Edit the generated files with your settings:
   # - .env: Add your JFrog credentials
   # - config.local.yaml: Customize any settings
   ```

3. **Verify setup**
   ```bash
   python cli.py config validate
   python cli.py health check
   ```

## 📋 Usage

The tool provides two entry points with support for both UV and traditional Python environments:

1. **`python -m src.main`** - Core CLI with basic scan and status operations
2. **`cli.py`** - Comprehensive testing and administration tool

### Core CLI Commands

#### Using UV (Recommended)
```bash
# Basic security scan
uv run python -m src.main --scan
uv run python -m src.main  # Default: runs scan

# Health check
uv run python -m src.main --status
```

#### Using pip/venv (Traditional)
```bash
source venv/bin/activate  # Activate virtual environment first

# Basic security scan
python -m src.main --scan
python -m src.main  # Default: runs scan

# Health check
python -m src.main --status
```

### Comprehensive CLI (cli.py)

#### Using UV (Recommended)
```bash
# Health check
uv run python cli.py health check

# Search for packages
uv run python cli.py registry search <package-name>
uv run python cli.py registry search axios npm

# Package blocking and management
uv run python cli.py registry block <package-name> <ecosystem> <version>
uv run python cli.py registry block axios npm 1.12.2
uv run python cli.py registry unblock axios npm 1.12.2
uv run python cli.py registry list-blocked npm

# Security cross-reference scan
uv run python cli.py scan crossref
uv run python cli.py scan crossref --hours 24

# Test security scan
uv run python cli.py scan test

# Interactive mode
uv run python cli.py interactive
```

#### Using pip/venv (Traditional)

**Health Check**
```bash
python cli.py health check
```
Validates connection to your JFrog Artifactory instance and other services.

**Search for Packages**
```bash
python cli.py registry search <package-name>
python cli.py registry search axios npm
```
Search for specific packages in your JFrog repositories.

**Package Blocking and Management**
```bash
# Block malicious packages
python cli.py registry block <package-name> <ecosystem> <version>
python cli.py registry block axios npm 1.12.2

# View blocked packages
python cli.py registry list-blocked npm

# Unblock packages
python cli.py registry unblock axios npm 1.12.2
```
Block, unblock, and manage malicious packages using JFrog exclusion patterns.

**Security Cross-Reference Scan**
```bash
python cli.py scan crossref
python cli.py scan crossref --hours 24
python cli.py scan crossref --hours 6 --ecosystem npm --limit 100
```
Fetches malicious packages from OSV (last 6 hours by default) and searches for them in your JFrog repositories.

**Test Security Scan**
```bash
python cli.py scan test
```
Runs a test scan with known packages to validate the system.

### Simplified Entry Point (python -m src.main)

**Basic Health Check**
```bash
python -m src.main --status
```

**Basic Security Scan**
```bash
python -m src.main --scan
```

### Interactive Mode

```bash
python cli.py interactive
```
Start an interactive session with autocomplete and command history.

### Cron Usage

For scheduled scans, use the core entry point:
```bash
# Run security scan every 6 hours
0 */6 * * * cd /path/to/malifiscan && python -m src.main --scan

# Daily health check
0 9 * * * cd /path/to/malifiscan && python -m src.main --status
```

## 🧪 Testing

Testing guidelines, database persistence strategy, and detailed command usage have moved to `CONTRIBUTING.md`.

Quick commands:
```bash
uv run pytest tests/                 # All tests (UV)
pytest tests/                        # All tests (pip/venv)
```

For database best practices, coverage instructions, integration test markers, and adding new tests, see the Testing section in `CONTRIBUTING.md`.

## 🔧 Configuration

Malifiscan uses a layered configuration approach for maximum flexibility and user-friendliness.

### Quick Start Configuration

```bash
# Initialize configuration files (one-time setup)
python cli.py config init

# Validate your configuration
python cli.py config validate

# View current configuration
python cli.py config show
```

### Configuration Layers (Priority Order)

Configuration is loaded from multiple sources, with higher priority sources overriding lower ones:

1. **CLI arguments** (highest priority)
2. **Environment variables** (`.env` file or system environment)
3. **Local config file** (`config.local.yaml` - user-specific, gitignored)
4. **Project config file** (`config.yaml` - defaults, committed to Git)
5. **Built-in defaults** (lowest priority)

### Configuration Files

#### Environment Variables (.env)

Contains sensitive information like credentials and API keys:

```bash
# JFrog Configuration (Required)
JFROG_BASE_URL=https://your-company.jfrog.io/artifactory
JFROG_API_KEY=your-api-key-here

# Optional: Customize scan behavior
SCANNER_INTERVAL_HOURS=1
LOG_LEVEL=INFO
```

#### Local Configuration (config.local.yaml)

Your personal configuration overrides (gitignored):

```yaml
# Enable debug mode for development
debug: true
environment: development

# Override service configurations
packages_registry:
  enabled: true
  config:
    timeout_seconds: 60

# Custom storage location
storage_service:
  type: file
  config:
    data_directory: "my_scan_results"
```

#### Base Configuration (config.yaml)

Project defaults (committed to Git):

```yaml
packages_feed:
  type: osv
  enabled: true

packages_registry:
  type: jfrog  
  enabled: true

notification_service:
  type: null
  enabled: false

storage_service:
  type: file
  enabled: true
```

## � Sample Output

**Security Cross-Reference Scan:**
```
🔍 Security Cross-Reference Scan
Fetching malicious packages from OSV (last 48 hours)...
✅ Found 327 malicious packages from OSV

🔍 Searching in JFrog repositories...
Processing packages ━━━━━━━━━━━━━━━━━━━━━━━━ 100% 327/327

📊 Security Scan Results
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃ Metric          ┃ Count   ┃ Status ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ Packages Scanned│ 327     │ ✅     │
│ Found in JFrog  │ 0       │ ✅     │
│ Processing Errors│ 3      │ ⚠️     │
└─────────────────┴─────────┴────────┘

🎉 No malicious packages found in your repositories!
```

**Package Search:**
```
🔍 Searching for package: axios

📊 Search Results for 'axios'
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Repository                                  ┃ Version                                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ npm-local                                   │ 1.12.2                                     │
│ npm-virtual                                 │ 1.12.2                                     │
└─────────────────────────────────────────────┴────────────────────────────────────────────┘

✅ Found 2 results for 'axios'
```

## ⚡ Performance Considerations

When using exclusion patterns for package blocking:

- **Moderate Impact**: JFrog evaluates exclusion patterns for every artifact request
- **Recommended Limits**: Monitor performance with 100-500 patterns initially
- **Pattern Optimization**: Use specific patterns rather than broad wildcards
- **Monitoring**: Track JFrog performance metrics when implementing at scale

For high-volume repositories, consider:
- Grouping similar patterns when possible
- Keeping pattern strings under 10KB total
- Regular cleanup of obsolete patterns

## 🔒 Security Notes

- **Read-Only Operations**: The tool only reads from OSV and searches JFrog repositories
- **Manual Blocking**: Packages are only blocked when explicitly requested via CLI commands
- **Pattern Safety**: Existing exclusion patterns are preserved using union-based merging
- **Audit Trail**: All scans and blocking operations are logged for audit purposes
- **Credential Security**: Credentials are only used for JFrog API access and stored locally

## 📚 Documentation

- **CONTRIBUTING.md**: Development setup, architecture, and contribution guidelines
- **STANDARDS.md**: Coding standards and best practices
- **TESTING.md**: Testing procedures and coverage requirements

## 🆘 Troubleshooting

**Common Issues:**

- **JFrog Connection Failed**: Verify JFROG_BASE_URL and JFROG_API_KEY in .env file
- **OSV Timeout**: Check internet connectivity and try again
- **No Results Found**: Package may not be in your repositories or ecosystem filter may be incorrect

**Get Help:**
```bash
python cli.py --help
python cli.py <command> --help
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**⚠️ Note**: This tool is for security assessment purposes. Always validate results before taking action on package repositories.