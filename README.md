# AZO TOOLKIT

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

> **DISCLAIMER: This tool is for educational and authorized security testing purposes only. Use responsibly and in compliance with applicable laws and regulations.**

## Overview

AZO Toolkit (formerly AZO CCTV Scanner) is a comprehensive, modular Python tool designed for security testing and system analysis. Built with modern Python practices, it provides advanced scanning capabilities with a focus on security research and penetration testing.

### Key Features

- **Multi-Source Scanning**: Integrated with Insecam, Shodan, and Censys
- **Credential Testing**: Comprehensive database of default credentials
- **Vulnerability Scanning**: XSS, SQL injection, command injection, path traversal
- **Device Fingerprinting**: Vendor detection, model identification, technology stack analysis
- **Async Performance**: High-performance concurrent scanning
- **Web Dashboard**: Real-time monitoring and results visualization
- **Docker Support**: Containerized deployment
- **Comprehensive Reporting**: JSON, CSV, and text report formats
- **Modular Architecture**: Extensible and maintainable codebase

## Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Development](#-development)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/09AZO14/AZO-CCTV-Scanner.git
cd AZO-CCTV-Scanner

# Install the package
pip install -e .
```

### Development Installation

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Setup pre-commit hooks
pre-commit install
```

### Docker Installation

```bash
# Build Docker image
docker build -t azo-cctv:latest .

# Run container
docker run -p 8000:8000 -v $(pwd)/azo_results:/app/azo_results azo-cctv:latest
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

## Quick Start

### Command Line Interface

```bash
# Show help
azo-cctv --help

# Scan single target
azo-cctv scan single http://192.168.1.100

# Scan by country
azo-cctv scan country US --max-pages 5

# Scan from file
azo-cctv scan file targets.txt

# Interactive mode
azo-cctv interactive

# Show configuration
azo-cctv config show

# Generate report
azo-cctv report generate
```

### Web Dashboard

```bash
# Start web server
azo-cctv web --host 0.0.0.0 --port 8000

# Or using uvicorn directly
uvicorn azo_cctv.web.app:create_app --host 0.0.0.0 --port 8000 --reload
```

Access the dashboard at: http://localhost:8000

## Usage

### Command Line Options

#### Single Target Scan

```bash
azo-cctv scan single <target> [OPTIONS]

Options:
  --timeout INTEGER     Request timeout in seconds [default: 5]
  --workers INTEGER     Number of concurrent workers [default: 10]
  --rate-limit FLOAT    Rate limit between requests [default: 0.5]
  --stealth             Enable stealth mode (fewer requests)
  --output PATH         Output directory for results
```

#### Country Scan

```bash
azo-cctv scan country <country_code> [OPTIONS]

Options:
  --max-pages INTEGER   Maximum pages to scan [default: 10]
  --max-results INTEGER Maximum results to return [default: 100]
  --timeout INTEGER     Request timeout in seconds [default: 5]
  --workers INTEGER     Number of concurrent workers [default: 10]
  --rate-limit FLOAT    Rate limit between requests [default: 0.5]
```

#### File Scan

```bash
azo-cctv scan file <file_path> [OPTIONS]

Options:
  --timeout INTEGER     Request timeout in seconds [default: 5]
  --workers INTEGER     Number of concurrent workers [default: 10]
  --rate-limit FLOAT    Rate limit between requests [default: 0.5]
  --country TEXT        Country code for statistics
```

### Configuration

The scanner uses a hierarchical configuration system:

1. **Environment Variables**: Highest priority
2. **Configuration File**: `config.json` or `config.yaml`
3. **Default Values**: Built-in defaults

#### Environment Variables

```bash
# API Keys
export AZO_SHODAN_KEY="your_shodan_api_key"
export AZO_CENSYS_ID="your_censys_id"
export AZO_CENSYS_SECRET="your_censys_secret"

# Scanner Settings
export AZO_TIMEOUT="10"
export AZO_MAX_WORKERS="20"
export AZO_RATE_LIMIT="0.5"

# Output Settings
export AZO_OUTPUT_DIR="./azo_results"
export AZO_LOG_LEVEL="INFO"
```

#### Configuration File

Create `config.json`:

```json
{
  "api": {
    "shodan_key": "your_shodan_api_key",
    "censys_id": "your_censys_id",
    "censys_secret": "your_censys_secret"
  },
  "scanner": {
    "timeout": 10,
    "max_workers": 20,
    "rate_limit": 0.5,
    "stealth_mode": false
  },
  "data_sources": {
    "insecam_enabled": true,
    "shodan_enabled": true,
    "censys_enabled": true,
    "max_pages": 10,
    "max_results": 100
  },
  "output": {
    "directory": "./azo_results",
    "log_level": "INFO",
    "log_format": "json"
  }
}
```

### Python API

```python
from azo_cctv.core.scanner import AZOScanner
from azo_cctv.core.config import Config

# Initialize scanner
config = Config()
scanner = AZOScanner(config)

# Scan single target
result = scanner.scan_target("http://192.168.1.100")
print(f"Target accessible: {result['accessible']}")
print(f"Credentials found: {len(result['credentials'])}")
print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")

# Mass scan
targets = ["http://192.168.1.100", "http://192.168.1.101"]
results = scanner.mass_scan(targets)

# Generate report
report_path = scanner.generate_report()
print(f"Report generated: {report_path}")
```

## Configuration

### Scanner Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `timeout` | 5 | Request timeout in seconds |
| `max_workers` | 10 | Maximum concurrent workers |
| `rate_limit` | 0.5 | Rate limit between requests |
| `stealth_mode` | false | Enable stealth mode |

### Data Sources

| Source | Enabled | Description |
|--------|---------|-------------|
| Insecam | true | Free camera database |
| Shodan | true | Internet-wide scanner (requires API key) |
| Censys | true | Internet-wide scanner (requires API key) |

### Output Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `directory` | `./azo_results` | Output directory |
| `log_level` | `INFO` | Logging level |
| `log_format` | `json` | Log format (json/text) |

## API Reference

### Core Classes

#### `AZOScanner`

Main scanner class with async support.

```python
class AZOScanner:
    def __init__(self, config: Config)
    async def scan_target_async(self, target: str) -> Dict[str, Any]
    def scan_target(self, target: str) -> Dict[str, Any]
    async def mass_scan_async(self, targets: List[str]) -> List[Dict[str, Any]]
    def mass_scan(self, targets: List[str]) -> List[Dict[str, Any]]
    def generate_report(self) -> str
```

#### `Config`

Configuration management class.

```python
class Config:
    def __init__(self, config_file: Optional[str] = None)
    def validate(self) -> None
    def to_dict(self) -> Dict[str, Any]
    def save(self, file_path: str) -> None
```

### Data Sources

#### `InsecamSource`

Insecam camera database integration.

```python
class InsecamSource(DataSource):
    async def fetch_cameras(self, country_code: str) -> List[Dict[str, Any]]
```

#### `ShodanSource`

Shodan API integration.

```python
class ShodanSource(DataSource):
    async def fetch_cameras(self, country_code: str) -> List[Dict[str, Any]]
```

### Scanners

#### `CredentialScanner`

Default credential testing.

```python
class CredentialScanner:
    async def scan_async(self, target_url: str) -> List[Dict[str, Any]]
```

#### `VulnerabilityScanner`

Vulnerability detection.

```python
class VulnerabilityScanner:
    async def scan_async(self, target_url: str) -> List[Dict[str, Any]]
```

#### `FingerprintScanner`

Device fingerprinting.

```python
class FingerprintScanner:
    async def scan_async(self, target_url: str) -> Dict[str, Any]
```

## Development

### Project Structure

```
azo_cctv/
├── core/                 # Core functionality
│   ├── config.py        # Configuration management
│   ├── exceptions.py    # Custom exceptions
│   └── scanner.py       # Main scanner class
├── sources/             # Data sources
│   ├── base.py          # Abstract base class
│   ├── insecam.py       # Insecam integration
│   ├── shodan.py        # Shodan integration
│   └── censys.py        # Censys integration
├── scanners/            # Scanning modules
│   ├── credential.py    # Credential testing
│   ├── vulnerability.py # Vulnerability scanning
│   └── fingerprint.py   # Device fingerprinting
├── utils/               # Utilities
│   ├── http.py          # HTTP client
│   ├── logging.py       # Logging utilities
│   └── validators.py    # Input validation
├── cli/                 # Command line interface
│   └── main.py          # CLI entry point
├── web/                 # Web dashboard
│   └── app.py           # FastAPI application
└── tests/               # Test suite
    └── test_scanner.py  # Unit tests
```

### Development Commands

```bash
# Setup development environment
make dev-setup

# Run tests
make test

# Run tests with coverage
make test-cov

# Format code
make format

# Check formatting
make format-check

# Run linting
make lint

# Run security checks
make security-check

# Run all CI checks
make ci

# Build package
make build

# Clean build artifacts
make clean
```

### Adding New Features

1. **Data Sources**: Extend `DataSource` base class
2. **Scanners**: Create new scanner modules
3. **CLI Commands**: Add to `cli/main.py`
4. **Web Endpoints**: Add to `web/app.py`
5. **Tests**: Add corresponding test files

### Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest azo_cctv/tests/test_scanner.py

# Run with coverage
pytest --cov=azo_cctv --cov-report=html

# Run integration tests
pytest -m integration

# Run unit tests only
pytest -m unit
```

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Add** tests for new functionality
5. **Run** the test suite
6. **Submit** a pull request

### Development Setup

```bash
# Fork and clone
git clone https://github.com/your-username/AZO-CCTV-Scanner.git
cd AZO-CCTV-Scanner

# Setup development environment
make dev-setup

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
make test
make lint

# Commit with conventional commits
git commit -m "feat: add new scanner module"

# Push and create PR
git push origin feature/your-feature-name
```

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Use [isort](https://pycqa.github.io/isort/) for imports
- Use [mypy](https://mypy.readthedocs.io/) for type checking

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Maintenance tasks

## Security



### Security Features

- Input validation and sanitization
- Rate limiting and request throttling
- Secure HTTP client with retry logic
- Comprehensive error handling
- Logging and audit trails

### Best Practices

- Use in authorized environments only
- Respect rate limits and terms of service
- Follow responsible disclosure
- Keep API keys secure
- Monitor and log usage

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Insecam**: For providing camera database
- **Shodan**: For internet-wide scanning capabilities
- **Censys**: For comprehensive network data
- **FastAPI**: For modern web framework
- **Click**: For elegant CLI framework
- **aiohttp**: For async HTTP client

## Support

- **Documentation**: [GitHub Wiki](https://github.com/09AZO14/AZO-CCTV-Scanner/wiki)
- **Issues**: [GitHub Issues](https://github.com/09AZO14/AZO-CCTV-Scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/09AZO14/AZO-CCTV-Scanner/discussions)

---

**NOTICE**: This tool is for educational and authorized security testing purposes only. Always use responsibly and in compliance with applicable laws and regulations. 
