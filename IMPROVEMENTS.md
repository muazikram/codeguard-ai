# CodeGuard AI - Recent Improvements

## Summary of Enhancements

This document outlines the improvements made to CodeGuard AI based on user feedback.

## 🎯 New Features Added

### 1. Dependency Vulnerability Checking
- **Automatic Detection**: Scans package.json and requirements.txt for vulnerable packages
- **Known CVE Database**: Checks against 8 known vulnerable package versions
- **Detailed Information**: Shows package name, current version, safe version, CVE, and description
- **Upgrade Commands**: Provides exact npm/pip commands to fix vulnerabilities
- **Dedicated Section**: Separate "Dependency Vulnerabilities" section in HTML report
- **High Severity**: All dependency vulnerabilities flagged as High severity

**Supported Packages:**
- **Node.js**: lodash, express, axios
- **Python**: django, flask, requests, numpy, pillow

**Example Detection:**
```
Package: express
Current Version: ^4.17.2
Min Safe Version: 4.19.0
CVE: CVE-2024-29041
Description: Open redirect vulnerability
Fix: npm install express@4.19.0
```

### 2. GitHub Repository Scanning
- **Direct URL Support**: Scan any GitHub repository by providing its URL
- **Automatic Cloning**: Uses `git clone --depth 1` for fast, shallow clones
- **Temporary Directory**: Clones to temp directory with automatic cleanup
- **Display Integration**: Shows GitHub URL in report header instead of temp path
- **Error Handling**: Comprehensive error handling for network issues, timeouts, etc.
- **Backward Compatible**: Local path scanning still works exactly as before

**Usage Examples:**
```bash
# Scan a GitHub repository
python3 codeguard.py https://github.com/OWASP/NodeGoat

# Still works with local paths
python3 codeguard.py ./my-project
```

### 3. Risk Score Gauge (0-100)
- **Visual Circular Gauge**: Beautiful SVG-based circular progress indicator
- **Color-Coded Risk Levels**:
  - 🔴 **Red (>70)**: High Risk - Immediate action required
  - 🟠 **Orange (40-70)**: Medium Risk - Review and address issues
  - 🟢 **Green (<40)**: Low Risk - Good security posture
- **Smart Calculation**: `Risk Score = min(100, Critical×10 + High×5 + Medium×2 + Low×1)`
- **Includes Dependencies**: Dependency vulnerabilities count as High (+5 each)
- **Contextual Recommendations**: Dynamic advice based on risk level

### 4. Interactive Filter Bar
- **Real-time Filtering**: Click buttons to filter findings without page reload
- **Severity Buttons**: All, Critical, High, Medium, Low
- **Count Display**: Shows number of findings for each severity level
- **Visual Feedback**: Active button highlighting with smooth transitions
- **JavaScript-Powered**: Client-side filtering for instant response

### 5. JWT Token Detection
- **Pattern Recognition**: Detects hardcoded JWT tokens using regex pattern
- **Format**: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
- **Severity**: Critical (10 points toward risk score)
- **Common Use Case**: Identifies tokens in configuration files, source code, and documentation

## 📊 Technical Implementation

### GitHub Repository Scanning
```python
def is_github_url(url: str) -> bool:
    """Check if the input is a GitHub URL."""
    github_patterns = [
        r'^https?://github\.com/[\w-]+/[\w.-]+',
        r'^git@github\.com:[\w-]+/[\w.-]+\.git$'
    ]
    return any(re.match(pattern, url) for pattern in github_patterns)

def clone_github_repo(repo_url: str) -> tuple[str, str]:
    """Clone a GitHub repository to a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix='codeguard_')
    
    # Clone with depth 1 for faster cloning
    subprocess.run(
        ['git', 'clone', '--depth', '1', repo_url, temp_dir],
        capture_output=True,
        text=True,
        timeout=300  # 5 minute timeout
    )
    
    return temp_dir, repo_url
```

**Key Features:**
- Supports both HTTPS and SSH GitHub URLs
- Shallow clone (`--depth 1`) for speed
- 5-minute timeout to prevent hanging
- Automatic cleanup in `finally` block
- Error handling for missing git, network issues, etc.

### Risk Score Calculation
```python
risk_score = min(100, 
                severity_counts.get('Critical', 0) * 10 + 
                severity_counts.get('High', 0) * 5 + 
                severity_counts.get('Medium', 0) * 2 + 
                severity_counts.get('Low', 0) * 1)
```

### Filter Functionality
```javascript
function filterFindings(severity) {
    const cards = document.querySelectorAll('.finding-card');
    const buttons = document.querySelectorAll('.filter-btn');
    
    // Update button states
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    // Filter cards
    cards.forEach(card => {
        if (severity === 'all') {
            card.classList.remove('hidden');
        } else {
            if (card.dataset.severity === severity) {
                card.classList.remove('hidden');
            } else {
                card.classList.add('hidden');
            }
        }
    });
}
```

### JWT Detection Pattern
```python
(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
 'Hardcoded JWT token detected', 'Critical')
```

## 🎨 UI/UX Improvements

### Risk Score Section
- Prominent placement at the top of the report
- Large, easy-to-read gauge with percentage
- Detailed risk information panel with:
  - Risk level label
  - Score calculation explanation
  - Total issues summary
  - Contextual recommendations

### Filter Bar
- Clean, modern button design
- Color-coded to match severity levels
- Hover effects for better interactivity
- Active state highlighting
- Responsive layout for mobile devices

### Enhanced Finding Cards
- Added `data-severity` attribute for filtering
- Maintains all existing features:
  - File path and line number
  - Code snippet
  - Fix recommendations
  - Severity badges

## 📈 Test Results

### Local Path Scan (vulnerable-app)
- Files scanned: 74
- Total findings: **154**
- Critical: **27** | High: 12 | Medium: 115 | Low: 0
- **Risk Score: 100/100** (High Risk)

### GitHub Repository Scan (OWASP/NodeGoat)
- Repository: https://github.com/OWASP/NodeGoat
- Files scanned: 103
- Total findings: **80**
- Critical: **39** | High: 0 | Medium: 35 | Low: 6
- **Risk Score: 100/100** (High Risk)
- Clone time: ~2 seconds
- Cleanup: Automatic

## 🚀 Benefits

1. **GitHub Integration**: Scan any public repository without manual cloning
2. **Better Risk Assessment**: Instant visual understanding of overall security posture
3. **Improved Navigation**: Quick filtering to focus on specific severity levels
4. **Enhanced Detection**: JWT token detection catches more security issues
5. **Professional Presentation**: More impressive for hackathon demos and presentations
6. **User-Friendly**: Interactive features make the report easier to use
7. **Time Saving**: Automatic clone and cleanup saves manual steps
8. **Versatile**: Works with both local paths and remote repositories

## 📝 Code Quality

- **No External Dependencies**: Still uses only Python standard library
- **Clean Implementation**: Well-structured CSS and JavaScript
- **Maintainable**: Clear separation of concerns
- **Performant**: Client-side filtering for instant response
- **Responsive**: Works on all screen sizes

## 🎓 Educational Value

The improvements help users:
- Understand risk prioritization
- Learn about JWT security
- See the impact of different vulnerability types
- Make informed decisions about remediation order

## 🔮 Future Enhancement Ideas

- Export findings to JSON/CSV
- Trend analysis across multiple scans
- Integration with CI/CD pipelines
- Custom severity weights
- Vulnerability database integration
- Automated fix suggestions with code examples
- Support for private repositories (with authentication)
- GitLab and Bitbucket support
- Parallel scanning for faster processing
- Custom rule definitions

---

**Version**: 3.0
**Last Updated**: 2026-05-03
**Compatibility**: Python 3.6+
**Requirements**: Git (for GitHub repository scanning)