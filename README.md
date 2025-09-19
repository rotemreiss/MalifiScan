# OSV-JFrog Security Scanner

A security tool that detects malicious packages from the OSV (Open Source Vulnerabilities) database and searches for them in your JFrog Artifactory repositories.

## 🛡️ Features

- **OSV Feed Integration**: Fetches malicious package data from Google Cloud Storage OSV vulnerability database
- **JFrog Artifactory Search**: Searches for packages in your Artifactory repositories using AQL (Artifactory Query Language)
- **Security Cross-Reference**: Compares OSV malicious packages against your JFrog repositories to identify potential threats
- **Time-Based Filtering**: Configurable time window for fetching recent malicious packages (default: 48 hours)
- **Rich CLI Interface**: Interactive command-line interface with progress bars and formatted output
- **Comprehensive Health Checks**: Validates connectivity to OSV and JFrog services

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- JFrog Artifactory instance with API access
- Internet connectivity for OSV database access

### Installation

#### Option 1: Using UV (Recommended)

UV is a fast Python package manager that provides better dependency resolution and faster installs.

1. **Install UV** (if not already installed)
   ```bash
   # Using the official installer
   curl -LsSf https://astral.sh/uv/install.sh | sh
   # Or visit: https://docs.astral.sh/uv/getting-started/installation/
   ```

2. **Clone and setup the project**
   ```bash
   git clone <repository-url>
   cd osv-jfrog
   
   # Initialize UV project and install dependencies
   uv init --no-readme --no-pin-python
   uv sync --dev
   ```

3. **Configure JFrog connection**
   ```bash
   # Create .env file from example (if available) or create new one
   cp .env.example .env  # If .env.example exists
   
   # Edit .env with your JFrog details:
   # JFROG_BASE_URL=https://your-company.jfrog.io
   # JFROG_ACCESS_TOKEN=your-access-token
   # JFROG_REPOSITORY=your-repo-name
   ```

4. **Make CLI executable**
   ```bash
   chmod +x cli.py
   ```

#### Option 2: Using pip (Traditional)

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd osv-jfrog
   
   # Create and activate virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Upgrade pip and install dependencies
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. **Configure JFrog connection**
   ```bash
   # Create .env file from example (if available) or create new one
   cp .env.example .env  # If .env.example exists
   
   # Edit .env with your JFrog details:
   # JFROG_BASE_URL=https://your-company.jfrog.io
   # JFROG_ACCESS_TOKEN=your-access-token
   # JFROG_REPOSITORY=your-repo-name
   ```

3. **Make CLI executable**
   ```bash
   chmod +x cli.py
   ```

#### Environment Configuration

If `.env.example` doesn't exist, create a `.env` file with the following template:

```bash
# JFrog Artifactory Configuration
JFROG_BASE_URL=https://your-instance.jfrog.io
JFROG_ACCESS_TOKEN=your-access-token
JFROG_REPOSITORY=your-repo-name

# Scanner Configuration  
SCAN_INTERVAL_HOURS=24
LOG_LEVEL=INFO
STORAGE_TYPE=memory

# OSV Database Configuration
OSV_API_BASE_URL=https://api.osv.dev
OSV_BATCH_SIZE=100
```

**⚠️ Important**: Edit the `.env` file with your actual JFrog credentials before running the tool.

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
uv run python cli.py jfrog search <package-name>
uv run python cli.py jfrog search axios
uv run python cli.py jfrog search react npm

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
python cli.py jfrog search <package-name>
python cli.py jfrog search axios
python cli.py jfrog search react npm
```
Search for specific packages in your JFrog repositories.

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
0 */6 * * * cd /path/to/osv-jfrog && python -m src.main --scan

# Daily health check
0 9 * * * cd /path/to/osv-jfrog && python -m src.main --status
```

## 🧪 Testing

### Using UV (Recommended)
```bash
# Run all tests
uv run pytest tests/

# Run only unit tests (faster)
uv run pytest tests/ -m "not integration"

# Run only integration tests
uv run pytest tests/ -m integration

# Run with coverage
uv run pytest tests/ --cov=src --cov-report=html

# Run tests with custom pytest options
uv run pytest tests/ --verbose --tb=short
uv run pytest tests/ -k "test_jfrog"
```

### Using pip/venv (Traditional)
```bash
source venv/bin/activate  # Activate environment first

# Run all tests
pytest tests/

# Run only unit tests
pytest tests/ -m "not integration"

# Run only integration tests  
pytest tests/ -m integration

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Command Options

- `--hours`: Time window for OSV data (default: 48)
- `--ecosystem`: Package ecosystem (npm, pypi, etc.) 
- `--limit`: Maximum number of packages to process
- `--debug`: Enable detailed logging

## 🔧 Configuration

### Environment Variables (.env)

```bash
# JFrog Configuration (Required)
JFROG_BASE_URL=https://your-company.jfrog.io/artifactory
JFROG_API_KEY=your-api-key-here

# Optional: Customize scan behavior
SCANNER_INTERVAL_HOURS=1
```

### Configuration File (config.yaml)

Enable/disable services and customize behavior:

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

## 🔒 Security Notes

- The tool only reads from OSV and searches JFrog repositories
- No packages are automatically blocked or modified
- All scans are logged for audit purposes
- Credentials are only used for JFrog API access

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