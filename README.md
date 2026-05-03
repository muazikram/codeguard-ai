# 🛡️ CodeGuard AI - Security Vulnerability Scanner

A comprehensive Python-based security vulnerability scanner designed for hackathons and security audits. CodeGuard AI scans your codebase and web applications for common security vulnerabilities and generates professional HTML reports.

## Features

### 💻 Code Scanning
- **Comprehensive Scanning**: Detects 14 categories of security vulnerabilities
- **Dependency Vulnerability Checking**: Automatically detects vulnerable package versions in package.json and requirements.txt
- **CI/CD Integration**: Built-in `--ci` mode for GitHub Actions and other CI/CD pipelines
- **Smart Filtering**: Automatically skips binary files, images, and common directories (node_modules, .git)
- **GitHub Repository Scanning**: Scan any public GitHub repository directly from URL
- **Export Options**: JSON and CSV export for automation and analysis

### 🌐 Web Security Analysis (NEW!)
- **Security Headers Analysis**: Checks for missing CSP, HSTS, X-Frame-Options, and more
- **SSL/TLS Certificate Validation**: Verifies certificate validity and expiration dates
- **Exposed Sensitive Files**: Detects publicly accessible config files, backups, and admin panels
- **JavaScript Secret Scanning**: Extracts and scans JS files for hardcoded secrets
- **Cookie Security**: Analyzes cookie attributes (Secure, HttpOnly, SameSite)

### 📊 Reporting
- **Professional Reports**: Beautiful, dark-themed HTML reports with severity-based color coding
- **Risk Score Gauge**: Visual 0-100 risk score with color-coded circular gauge
- **Interactive Filtering**: Click-to-filter findings by severity without page reload
- **Zero Dependencies**: Uses only Python standard library - no external packages required
- **Fast & Efficient**: Scans entire codebases and websites in seconds

## Vulnerability Detection

CodeGuard AI detects the following security issues across **14 categories**:

### 🔴 Critical Severity
- **Hardcoded Secrets**: Passwords, API keys, tokens, private keys
- **JWT Tokens**: Hardcoded JWT tokens (eyJ... pattern detection)
- **Dangerous Functions**: `eval()`, `exec()`, dynamic imports
- **Command Injection**: `shell=True` in subprocess calls
- **Path Traversal**: Directory traversal patterns (`../`), unsafe file operations
- **Disabled Security**: Password checks, authentication disabled

### 🟠 High Severity
- **Vulnerable Dependencies**: Outdated packages with known CVEs
  - lodash < 4.17.21 (Prototype pollution - CVE-2021-23337)
  - express < 4.19.0 (Open redirect - CVE-2024-29041)
  - axios < 1.6.0 (SSRF - CVE-2023-45857)
  - django < 3.2.19 (SQL injection - CVE-2023-31047)
  - flask < 2.3.0 (Multiple CVEs)
  - requests < 2.31.0 (Proxy issues - CVE-2023-32681)
  - numpy < 1.24.0 (Buffer overflow - CVE-2021-41496)
  - pillow < 9.3.0 (Code execution - CVE-2022-45198)
- **SQL Injection**: String concatenation in queries, unsafe query building
- **Weak Cryptography**: MD5, SHA1 for password hashing
- **Insecure Cookies**: Missing HttpOnly or Secure flags
- **Open Redirect**: Unvalidated redirects with user input
- **Prototype Pollution**: `__proto__`, `constructor.prototype` manipulation
- **Unsafe Deserialization**: pickle, YAML without SafeLoader
- **Disabled Authentication**: SSL verification, auth checks disabled
- **Information Disclosure**: Error details exposed in responses

### 🟡 Medium Severity
- **Missing Input Validation**: Direct access to request data
- **Insecure HTTP**: HTTP URLs instead of HTTPS
- **Exposed Stack Traces**: Error details printed/logged
- **Regex DoS**: Catastrophic backtracking patterns
- **Hardcoded Admin Checks**: Weak authorization logic

### 🔵 Low Severity
- **Hardcoded URLs**: IP addresses, endpoints in code
- **Console Logging**: Error information in console

## Installation

No installation required! Just download the script:

```bash
# Clone or download codeguard.py
wget https://your-repo/codeguard.py
# or
curl -O https://your-repo/codeguard.py
```

## Usage

### Code Scanning

Scan local directories or GitHub repositories for vulnerabilities:

```bash
python3 codeguard.py <folder_path_or_github_url> [--export json|csv] [--ci]
```

### Web Security Analysis

Perform passive security analysis of any website:

```bash
python3 codeguard.py --web <url>
```

### Ignoring Files and Directories

Create a `.codeguardignore` file in your project root to exclude files/directories from scanning:

```bash
# .codeguardignore example
# Lines starting with # are comments

# Ignore test directories
test/
tests/
__tests__/

# Ignore mock and fixture data
mock_data
fixtures/
mocks/

# Ignore specific files
README.md
package-lock.json

# Use regex patterns
.*\.test\.js$
.*\.spec\.ts$
```

**Pattern Matching:**
- Substring match: `test/` matches any path containing "test/"
- Regex support: `.*\.test\.js$` matches files ending with .test.js
- Comments: Lines starting with `#` are ignored
- Empty lines are ignored

The scanner will automatically load `.codeguardignore` if it exists in the scanned directory.

### Examples

#### Code Scanning Examples

Scan the current directory:
```bash
python3 codeguard.py .
```

Scan a specific project:
```bash
python3 codeguard.py /path/to/your/project
```

Scan a GitHub repository directly:
```bash
python3 codeguard.py https://github.com/user/repo
```

**Export to JSON:**
```bash
python3 codeguard.py ./my-project --export json
python3 codeguard.py https://github.com/user/repo --export json
```

**Export to CSV:**
```bash
python3 codeguard.py ./my-project --export csv
python3 codeguard.py https://github.com/user/repo --export csv
```

#### Web Security Analysis Examples

Analyze a website's security:
```bash
python3 codeguard.py --web https://example.com
```

Analyze your production site:
```bash
python3 codeguard.py --web https://myapp.com
```

Analyze a staging environment:
```bash
python3 codeguard.py --web https://staging.myapp.com
```

**What gets checked:**
- ✅ Security headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ SSL/TLS certificate validity and expiration
- ✅ Exposed sensitive files (/.env, /config.json, /admin, etc.)
- ✅ Cookie security attributes (Secure, HttpOnly, SameSite)
- ✅ JavaScript files for hardcoded secrets and API keys

**Note:** Web scanning is passive and only performs HTTP requests. No active exploitation or intrusive testing is performed.


### Export Formats

#### JSON Export (`report.json`)
- Complete scan information with metadata
- Structured data with code and dependency vulnerabilities
- Easy to parse programmatically
- Includes scan timestamp and file counts

#### CSV Export (`report.csv`)
- Spreadsheet-compatible format
- Columns: Type, Severity, Description, File, Line, Code Snippet, Recommendation
- Easy to open in Excel, Google Sheets, or any CSV viewer
- Includes both code and dependency findings

### GitHub Repository Scanning

The scanner will automatically:
1. Clone the repository to a temporary directory
2. Scan all files for vulnerabilities
3. Generate the report with the GitHub URL displayed
4. Clean up the temporary directory

### Output

The scanner will:
1. Display progress in the terminal
2. Show a summary of findings by severity
3. Generate `report.html` in the current directory (always)
4. Generate `report.json` or `report.csv` if `--export` flag is used

**HTML Report (`report.html`)** - Always generated:
- Summary dashboard with severity counts
- Detailed findings with file paths and line numbers
- Vulnerable code snippets
- Fix recommendations for each issue

## Report Features

The generated HTML report includes:

- **Dependency Vulnerabilities Section** - Dedicated section showing:
  - Package name and current version
  - Minimum safe version required
  - CVE identifier
  - Vulnerability description
  - Upgrade commands for npm/pip
- **Risk Score Gauge** - Circular gauge showing 0-100 risk score with color coding:
  - 🔴 Red (>70): High Risk - Immediate action required
  - 🟠 Orange (40-70): Medium Risk - Review and fix soon
  - 🟢 Green (<40): Low Risk - Good security posture
- **Interactive Filtering** - Click severity buttons to filter findings in real-time
- **Dark-themed professional dashboard** - Easy on the eyes
- **Severity-based color coding** - Quick visual identification
- **Interactive cards** - Hover effects for better UX
- **Complete context** - File path, line number, code snippet
- **Fix recommendations** - Actionable advice for each vulnerability
- **Scan metadata** - Timestamp, scanned path, file count
- **Responsive design** - Works on desktop and mobile

### Risk Score Calculation
```
Risk Score = min(100, Critical×10 + High×5 + Medium×2 + Low×1)
Note: Dependency vulnerabilities count as High severity (+5 points each)
```

## Example Output

```
============================================================
  CodeGuard AI - Security Vulnerability Scanner
============================================================

[*] Starting scan of: /path/to/project
[*] Timestamp: 2026-05-03 13:15:12
[*] Scan complete. Files scanned: 74
[*] Total findings: 154

============================================================
  Generating Report...
============================================================

[+] Report generated: /path/to/report.html

============================================================
  Scan Summary
============================================================
  Critical: 27
  High:     12
  Medium:   115
  Low:      0
  Total:    154
============================================================

[✓] Done! Open report.html in your browser to view the results.
```

**Risk Score:** 100/100 (High Risk - Immediate action required!)

## Excluded Files & Directories

### Automatic Exclusions

CodeGuard AI automatically skips:

**Directories:**
- `.git`, `node_modules`, `__pycache__`
- `.venv`, `venv`, `dist`, `build`, `.next`

**File Types:**
- Images: `.png`, `.jpg`, `.gif`, `.svg`, etc.
- Videos: `.mp4`, `.avi`, `.mov`, etc.
- Archives: `.zip`, `.tar`, `.gz`, etc.
- Documents: `.pdf`, `.doc`, `.xls`, etc.
- Binaries: `.exe`, `.dll`, `.so`, etc.

### Custom Exclusions (.codeguardignore)

Create a `.codeguardignore` file in your project root to exclude additional files:

```
# .codeguardignore example
test/
fixtures/
*.test.js
solutions/
```

**Features:**
- One pattern per line
- Substring matching: `test/` matches any path containing "test/"
- Regex support: `.*\.test\.js$` matches files ending with .test.js
- Comments: Lines starting with `#` are ignored
- Automatically loaded if present in scanned directory

## Technical Details

- **Language**: Python 3.6+
- **Dependencies**: None (uses only standard library)
  - **Note**: Git must be installed for GitHub repository scanning
- **File Size**: ~30KB (single file)
- **Performance**: Scans 100+ files in seconds
- **Report Size**: Varies based on findings (typically 1-5MB)
- **GitHub Support**: Automatically clones and scans repositories with cleanup

## CI/CD Integration

### GitHub Actions

CodeGuard AI includes a `--ci` flag for seamless CI/CD integration. A ready-to-use GitHub Actions workflow is provided.

#### Quick Setup

1. **Copy the workflow file** to your repository:
```bash
mkdir -p .github/workflows
cp .github/workflows/codeguard.yml .github/workflows/
```

2. **Update the workflow** (line 23) with your CodeGuard script location:
```yaml
# Option 1: If codeguard.py is in your repo
- name: Run CodeGuard Security Scan
  run: python3 codeguard.py . --ci

# Option 2: Download from a URL
- name: Download CodeGuard
  run: curl -o codeguard.py https://your-url/codeguard.py
```

3. **Commit and push** - The workflow will run on every pull request!

#### CI Mode Features

```bash
python3 codeguard.py . --ci
```

**Behavior:**
- ✅ Prints compact JSON summary to stdout
- ✅ No HTML report generated (faster execution)
- ✅ Exit code 0 if only Medium/Low findings
- ❌ Exit code 1 if any Critical or High findings
- 📊 Automatic PR comments with scan results

**JSON Output:**
```json
{
  "status": "fail",
  "scan_info": {
    "target": ".",
    "files_scanned": 74,
    "timestamp": "2026-05-03 14:15:32"
  },
  "severity_counts": {
    "Critical": 27,
    "High": 13,
    "Medium": 115,
    "Low": 0
  },
  "total_findings": 155,
  "critical_or_high": 40
}
```

### Other CI/CD Platforms

#### GitLab CI
```yaml
security_scan:
  stage: test
  script:
    - python3 codeguard.py . --ci
  allow_failure: false
```

#### Jenkins
```groovy
stage('Security Scan') {
    steps {
        sh 'python3 codeguard.py . --ci'
    }
}
```

#### CircleCI
```yaml
jobs:
  security-scan:
    docker:
      - image: python:3
    steps:
      - checkout
      - run: python3 codeguard.py . --ci
```

## Security Best Practices

CodeGuard AI helps you identify issues, but remember:

1. **Review all findings** - Some may be false positives
2. **Prioritize by severity** - Fix Critical and High issues first
3. **Use environment variables** - Never hardcode secrets
4. **Implement input validation** - Sanitize all user inputs
5. **Use parameterized queries** - Prevent SQL injection
6. **Enable HTTPS** - Encrypt data in transit
7. **Proper error handling** - Don't expose sensitive information
8. **Regular scans** - Make security scanning part of your workflow

## Limitations

- **Pattern-based detection**: May produce false positives
- **No runtime analysis**: Only scans static code
- **Language agnostic patterns**: Works best with common languages (Python, JavaScript, etc.)
- **Not a replacement**: Should be used alongside other security tools

## Use Cases

- **Hackathons**: Quick security audit of your project
- **Code Reviews**: Identify security issues before deployment
- **Learning**: Understand common security vulnerabilities
- **CI/CD Integration**: Add to your pipeline for automated scanning
- **Security Audits**: Initial assessment of codebases
- **GitHub Repository Analysis**: Scan any public repository directly from URL
- **Open Source Security**: Evaluate third-party dependencies and libraries

## Contributing

This is a hackathon project! Feel free to:
- Add more vulnerability patterns
- Improve detection accuracy
- Enhance the HTML report
- Add support for more languages

## License

MIT License - Free to use for any purpose

## Author

Created for hackathon security demonstrations and educational purposes.

---

**⚠️ Disclaimer**: This tool is for educational and security testing purposes. Always obtain proper authorization before scanning code you don't own. The tool may produce false positives - always verify findings manually.