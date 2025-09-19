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

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd osv-jfrog
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure JFrog connection**
   ```bash
   cp .env.example .env
   # Edit .env with your JFrog details:
   # JFROG_BASE_URL=https://your-company.jfrog.io
   # JFROG_API_KEY=your-api-key
   ```

## 📋 Usage

The tool provides two entry points:

1. **`python -m src.main`** - Core CLI with basic scan and status operations
2. **`cli.py`** - Comprehensive testing and administration tool

### Core CLI Commands (python -m src.main)

**Basic Security Scan**
```bash
python -m src.main --scan
python -m src.main  # Default: runs scan
```
Executes a complete security scan using the core functionality.

**Health Check**
```bash
python -m src.main --status
```
Shows service health and application status.

### Comprehensive CLI (cli.py)

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