# HeaderHound

A fast, opinionated command-line security scanner that analyzes HTTP response headers of target URLs. It instantly identifies missing or misconfigured security headers (like HSTS and CSP) and flags information disclosure leaks (like outdated server versions).

## Features
- **Comprehensive Rule Engine:** Checks for critical headers like `Strict-Transport-Security`, `X-Frame-Options`, and `Content-Security-Policy`.
- **Information Disclosure Detection:** Automatically flags `Server`, `X-Powered-By`, and ASP/PHP version leaks.
- **Developer-Friendly Output:** Beautiful, colored terminal output with actionable remediation advice.
- **JSON Export:** Save results directly to JSON for CI/CD integration or later review.
- **SSL Bypass:** A `--no-verify` flag to scan local development servers with self-signed certificates.

## Installation

Ensure you have Python 3.7+ installed.

```bash
# Clone the repository (or copy the files)
git clone https://github.com/yourusername/header-hound.git
cd header-hound

# Create a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (URL scheme defaults to https:// if omitted)
python main.py example.com

# Scan with verbose output (shows the values of passed headers)
python main.py https://github.com --verbose

# Bypass SSL verification for internal targets and export to JSON
python main.py https://10.0.0.50 --no-verify --json report.json
```

## Requirements
- Python 3.7+
- `requests` for robust HTTP fetching
- `colorama` for cross-platform ANSI terminal coloring
