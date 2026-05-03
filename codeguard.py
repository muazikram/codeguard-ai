#!/usr/bin/env python3
"""
CodeGuard AI - Security Vulnerability Scanner
A comprehensive security scanner for detecting common vulnerabilities in codebases.
"""

import os
import re
import sys
import json
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional

class VulnerabilityScanner:
    """Main scanner class for detecting security vulnerabilities."""
    
    # Directories to skip during scanning
    SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.next'}
    
    # File extensions to skip (images, binaries, etc.)
    SKIP_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
        '.mp4', '.avi', '.mov', '.mp3', '.wav',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.ttf', '.woff', '.woff2', '.eot',
        '.pyc', '.class', '.o', '.so', '.dll', '.exe'
    }
    
    def __init__(self, target_path: str, display_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve()
        self.display_path = display_path or str(self.target_path)
        self.findings: List[Dict] = []
        self.dependency_findings: List[Dict] = []
        self.files_scanned = 0
        self.ignore_patterns: List[str] = []
        
        # Load .codeguardignore if it exists
        self._load_ignore_patterns()
        
        # Known vulnerable package versions
        self.vulnerable_packages = {
            'lodash': {
                'min_safe': '4.17.21',
                'description': 'Prototype pollution vulnerability',
                'cve': 'CVE-2021-23337'
            },
            'express': {
                'min_safe': '4.19.0',
                'description': 'Open redirect vulnerability',
                'cve': 'CVE-2024-29041'
            },
            'axios': {
                'min_safe': '1.6.0',
                'description': 'SSRF vulnerability',
                'cve': 'CVE-2023-45857'
            },
            'django': {
                'min_safe': '3.2.19',
                'description': 'SQL injection vulnerability',
                'cve': 'CVE-2023-31047'
            },
            'flask': {
                'min_safe': '2.3.0',
                'description': 'Various security vulnerabilities',
                'cve': 'Multiple CVEs'
            },
            'requests': {
                'min_safe': '2.31.0',
                'description': 'Proxy authentication issues',
                'cve': 'CVE-2023-32681'
            },
            'numpy': {
                'min_safe': '1.24.0',
                'description': 'Buffer overflow vulnerability',
                'cve': 'CVE-2021-41496'
            },
            'pillow': {
                'min_safe': '9.3.0',
                'description': 'Arbitrary code execution',
                'cve': 'CVE-2022-45198'
            }
        }
        
        # Vulnerability patterns
        self.patterns = {
            'hardcoded_secrets': [
                (r'(?i)(password|passwd|pwd)\s*=\s*["\'](?!.*\$\{)(?!.*process\.env)(?!.*ENV)([^"\']{3,})["\']',
                 'Hardcoded password detected', 'Critical'),
                (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*=\s*["\'](?!.*\$\{)(?!.*process\.env)([^"\']{10,})["\']',
                 'Hardcoded API key detected', 'Critical'),
                (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'](?!.*\$\{)(?!.*process\.env)([^"\']{10,})["\']',
                 'Hardcoded secret key detected', 'Critical'),
                (r'(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)\s*=\s*["\']([A-Z0-9]{20,})["\']',
                 'Hardcoded AWS credentials detected', 'Critical'),
                (r'(?i)(token|auth[_-]?token|bearer)\s*=\s*["\'](?!.*\$\{)(?!.*process\.env)([^"\']{20,})["\']',
                 'Hardcoded authentication token detected', 'Critical'),
                (r'(?i)(private[_-]?key|privatekey)\s*=\s*["\']([^"\']{20,})["\']',
                 'Hardcoded private key detected', 'Critical'),
                (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                 'Hardcoded JWT token detected', 'Critical'),
            ],
            'sql_injection': [
                (r'(?i)(execute|query|exec)\s*\(\s*["\'].*?\+.*?["\']',
                 'Potential SQL injection via string concatenation', 'High'),
                (r'(?i)(execute|query|exec)\s*\(\s*f["\'].*?\{.*?\}',
                 'Potential SQL injection via f-string formatting', 'High'),
                (r'(?i)(execute|query|exec)\s*\(\s*["\'].*?%s.*?["\'].*?%',
                 'Potential SQL injection via string formatting', 'High'),
                (r'(?i)SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\+',
                 'SQL query with string concatenation detected', 'High'),
                (r'(?i)cursor\.execute\s*\([^)]*\+[^)]*\)',
                 'SQL execution with concatenation detected', 'High'),
            ],
            'dangerous_functions': [
                (r'\beval\s*\(',
                 'Use of dangerous eval() function', 'Critical'),
                (r'\bexec\s*\(',
                 'Use of dangerous exec() function', 'Critical'),
                (r'(?i)__import__\s*\(',
                 'Dynamic import detected - potential code injection', 'High'),
                (r'(?i)pickle\.loads?\s*\(',
                 'Unsafe deserialization with pickle', 'High'),
                (r'(?i)yaml\.load\s*\([^,)]*\)',
                 'Unsafe YAML loading without SafeLoader', 'High'),
                (r'(?i)subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                 'Command injection risk with shell=True', 'Critical'),
            ],
            'missing_validation': [
                (r'(?i)@app\.route\s*\([^)]*\).*?def\s+\w+\s*\([^)]*request',
                 'Route handler accessing request without visible validation', 'Medium'),
                (r'(?i)request\.(args|form|json|data)\[',
                 'Direct access to user input without validation', 'Medium'),
                (r'(?i)req\.(body|query|params)\.',
                 'Direct access to request data without validation', 'Medium'),
            ],
            'hardcoded_urls': [
                (r'(?i)(url|endpoint|host|server)\s*=\s*["\']https?://(?!localhost|127\.0\.0\.1|example\.com)([^"\']+)["\']',
                 'Hardcoded URL/endpoint detected', 'Low'),
                (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                 'Hardcoded IP address detected', 'Low'),
            ],
            'insecure_http': [
                (r'["\']http://(?!localhost|127\.0\.0\.1)([^"\']+)["\']',
                 'Insecure HTTP URL detected (should use HTTPS)', 'Medium'),
            ],
            'exposed_errors': [
                (r'(?i)except.*?:\s*print\s*\(',
                 'Exception details printed - potential information disclosure', 'Medium'),
                (r'(?i)console\.error\s*\(',
                 'Error logged to console - potential information disclosure', 'Low'),
                (r'(?i)traceback\.print_exc\s*\(',
                 'Stack trace printed - potential information disclosure', 'Medium'),
                (r'(?i)res\.send\s*\(\s*err',
                 'Error object sent in response - information disclosure', 'High'),
            ],
            'weak_auth': [
                (r'(?i)auth\s*=\s*False',
                 'Authentication disabled', 'High'),
                (r'(?i)verify\s*=\s*False',
                 'SSL verification disabled', 'High'),
                (r'(?i)check_password\s*=\s*False',
                 'Password check disabled', 'Critical'),
                (r'(?i)require_auth\s*=\s*False',
                 'Authentication requirement disabled', 'High'),
                (r'(?i)if\s+.*?==\s*["\']admin["\']',
                 'Hardcoded admin check detected', 'Medium'),
            ],
            'weak_crypto': [
                (r'hashlib\.md5\s*\(',
                 'Weak cryptography: MD5 used for hashing', 'High'),
                (r'hashlib\.sha1\s*\(',
                 'Weak cryptography: SHA1 used for hashing', 'High'),
                (r'(?i)MD5\s*\(',
                 'Weak cryptography: MD5 algorithm detected', 'High'),
                (r'(?i)SHA1\s*\(',
                 'Weak cryptography: SHA1 algorithm detected', 'High'),
            ],
            'insecure_cookies': [
                (r'set_cookie\s*\([^)]*\)(?!.*httponly\s*=\s*True)',
                 'Insecure cookie: HttpOnly flag not set', 'High'),
                (r'set_cookie\s*\([^)]*\)(?!.*secure\s*=\s*True)',
                 'Insecure cookie: Secure flag not set', 'High'),
            ],
            'path_traversal': [
                (r'\.\./|\.\.\\',
                 'Path traversal: Directory traversal pattern detected', 'Critical'),
                (r'open\s*\(\s*request\.',
                 'Path traversal: File operation with user input', 'Critical'),
                (r'os\.path\.join\s*\([^)]*request\.',
                 'Path traversal: Path join with user input', 'Critical'),
                (r'os\.path\.join\s*\([^)]*req\.',
                 'Path traversal: Path join with request data', 'Critical'),
            ],
            'open_redirect': [
                (r'redirect\s*\(\s*request\.',
                 'Open redirect: Redirect with user input', 'High'),
                (r'redirect\s*\(\s*params\.',
                 'Open redirect: Redirect with parameter input', 'High'),
                (r'window\.location\s*=\s*req\.',
                 'Open redirect: Client-side redirect with request data', 'High'),
                (r'location\.href\s*=\s*request\.',
                 'Open redirect: Location change with user input', 'High'),
            ],
            'prototype_pollution': [
                (r'__proto__',
                 'Prototype pollution: __proto__ manipulation detected', 'High'),
                (r'constructor\.prototype',
                 'Prototype pollution: Constructor prototype manipulation', 'High'),
                (r'\[.*?["\']__proto__["\']\]',
                 'Prototype pollution: Dynamic __proto__ access', 'High'),
            ],
            'regex_dos': [
                (r're\.compile\s*\([^)]*\([^)]*\+[^)]*\*',
                 'Regex DoS: Catastrophic backtracking pattern detected', 'Medium'),
                (r'RegExp\s*\([^)]*\([^)]*\+[^)]*\*',
                 'Regex DoS: Nested quantifiers in regex', 'Medium'),
                (r'Pattern\.compile\s*\([^)]*\([^)]*\+[^)]*\*',
                 'Regex DoS: Potentially vulnerable regex pattern', 'Medium'),
            ],
        }
    
    def _load_ignore_patterns(self):
        """Load ignore patterns from .codeguardignore file if it exists."""
        ignore_file = self.target_path / '.codeguardignore'
        if ignore_file.exists():
            try:
                with open(ignore_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # Skip empty lines and comments
                        if line and not line.startswith('#'):
                            self.ignore_patterns.append(line)
                if self.ignore_patterns:
                    print(f"[*] Loaded {len(self.ignore_patterns)} ignore patterns from .codeguardignore")
            except Exception as e:
                print(f"[!] Warning: Could not read .codeguardignore: {e}")
    
    def _should_ignore(self, file_path: str) -> bool:
        """Check if a file path should be ignored based on patterns."""
        if not self.ignore_patterns:
            return False
        
        for pattern in self.ignore_patterns:
            # Check if pattern is in the file path (substring match)
            if pattern in file_path:
                return True
            # Try regex match
            try:
                if re.search(pattern, file_path):
                    return True
            except re.error:
                # If regex is invalid, just use substring match
                pass
        
        return False
    
    def scan(self) -> List[Dict]:
        """Scan the target directory for vulnerabilities."""
        print(f"[*] Starting scan of: {self.target_path}")
        print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not self.target_path.exists():
            print(f"[!] Error: Path does not exist: {self.target_path}")
            sys.exit(1)
        
        if not self.target_path.is_dir():
            print(f"[!] Error: Path is not a directory: {self.target_path}")
            sys.exit(1)
        
        # Walk through all files
        for root, dirs, files in os.walk(self.target_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                
                # Skip files with excluded extensions
                if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
                    continue
                
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                
                self._scan_file(file_path)
        
        print(f"[*] Scan complete. Files scanned: {self.files_scanned}")
        print(f"[*] Total code findings: {len(self.findings)}")
        
        # Check for dependency vulnerabilities
        print(f"[*] Checking dependencies...")
        self._check_dependencies()
        print(f"[*] Total dependency findings: {len(self.dependency_findings)}")
        
        return self.findings
    
    def _check_dependencies(self):
        """Check for vulnerable dependencies in package.json and requirements.txt."""
        # Check package.json
        package_json_path = self.target_path / 'package.json'
        if package_json_path.exists():
            self._check_package_json(package_json_path)
        
        # Check requirements.txt
        requirements_path = self.target_path / 'requirements.txt'
        if requirements_path.exists():
            self._check_requirements_txt(requirements_path)
    
    def _check_package_json(self, file_path: Path):
        """Check package.json for vulnerable Node.js packages."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = {}
            if 'dependencies' in data:
                dependencies.update(data['dependencies'])
            if 'devDependencies' in data:
                dependencies.update(data['devDependencies'])
            
            for package, version in dependencies.items():
                if package in self.vulnerable_packages:
                    # Clean version string (remove ^, ~, >=, etc.)
                    clean_version = re.sub(r'[^0-9.]', '', version)
                    if clean_version and self._is_vulnerable_version(clean_version, self.vulnerable_packages[package]['min_safe']):
                        vuln_info = self.vulnerable_packages[package]
                        self.dependency_findings.append({
                            'package': package,
                            'version': version,
                            'min_safe_version': vuln_info['min_safe'],
                            'description': vuln_info['description'],
                            'cve': vuln_info['cve'],
                            'file': 'package.json',
                            'severity': 'High'
                        })
        except Exception as e:
            pass  # Skip if file can't be parsed
    
    def _check_requirements_txt(self, file_path: Path):
        """Check requirements.txt for vulnerable Python packages."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse package==version or package>=version
                match = re.match(r'([a-zA-Z0-9_-]+)\s*[=><]=?\s*([0-9.]+)', line)
                if match:
                    package = match.group(1).lower()
                    version = match.group(2)
                    
                    if package in self.vulnerable_packages:
                        if self._is_vulnerable_version(version, self.vulnerable_packages[package]['min_safe']):
                            vuln_info = self.vulnerable_packages[package]
                            self.dependency_findings.append({
                                'package': package,
                                'version': version,
                                'min_safe_version': vuln_info['min_safe'],
                                'description': vuln_info['description'],
                                'cve': vuln_info['cve'],
                                'file': 'requirements.txt',
                                'severity': 'High'
                            })
        except Exception as e:
            pass  # Skip if file can't be parsed
    
    def _is_vulnerable_version(self, current: str, min_safe: str) -> bool:
        """Compare version strings to determine if current version is vulnerable."""
        try:
            current_parts = [int(x) for x in current.split('.')]
            min_safe_parts = [int(x) for x in min_safe.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(current_parts), len(min_safe_parts))
            current_parts += [0] * (max_len - len(current_parts))
            min_safe_parts += [0] * (max_len - len(min_safe_parts))
            
            return current_parts < min_safe_parts
        except:
            return False
    
    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except:
            return True
    
    def _scan_file(self, file_path: Path):
        """Scan a single file for vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            self.files_scanned += 1
            
            for line_num, line in enumerate(lines, start=1):
                self._check_line(file_path, line_num, line)
        
        except Exception as e:
            # Skip files that can't be read
            pass
    
    def _check_line(self, file_path: Path, line_num: int, line: str):
        """Check a single line for vulnerability patterns."""
        for category, patterns in self.patterns.items():
            for pattern, description, severity in patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Get relative path
                    try:
                        rel_path = file_path.relative_to(self.target_path)
                    except:
                        rel_path = file_path
                    
                    rel_path_str = str(rel_path)
                    
                    # Check if this file should be ignored
                    if self._should_ignore(rel_path_str):
                        continue
                    
                    finding = {
                        'severity': severity,
                        'category': category,
                        'description': description,
                        'file': rel_path_str,
                        'line': line_num,
                        'code': line.strip(),
                        'recommendation': self._get_recommendation(category, description)
                    }
                    self.findings.append(finding)
    
    def _get_recommendation(self, category: str, description: str) -> str:
        """Get fix recommendation based on vulnerability type."""
        recommendations = {
            'hardcoded_secrets': 'Use environment variables or a secure secrets management system (e.g., AWS Secrets Manager, HashiCorp Vault). Never commit secrets to version control.',
            'sql_injection': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
            'dangerous_functions': 'Avoid using eval() and exec(). If absolutely necessary, sanitize and validate all inputs thoroughly. Consider safer alternatives.',
            'missing_validation': 'Implement input validation and sanitization. Use validation libraries and whitelist acceptable inputs.',
            'hardcoded_urls': 'Use configuration files or environment variables for URLs and endpoints. This improves flexibility and security.',
            'insecure_http': 'Use HTTPS instead of HTTP for all external communications to ensure data encryption in transit.',
            'exposed_errors': 'Log errors securely without exposing sensitive information. Use proper error handling and return generic error messages to users.',
            'weak_auth': 'Implement proper authentication and authorization. Never disable security checks in production code.',
            'weak_crypto': 'Use strong cryptographic algorithms like SHA-256, SHA-512, or bcrypt for password hashing. Avoid MD5 and SHA1 as they are cryptographically broken.',
            'insecure_cookies': 'Set HttpOnly and Secure flags on all cookies. HttpOnly prevents XSS attacks, Secure ensures cookies are only sent over HTTPS.',
            'path_traversal': 'Validate and sanitize all file paths. Use allowlists for permitted directories. Never directly use user input in file operations.',
            'open_redirect': 'Validate redirect URLs against an allowlist. Never redirect to user-supplied URLs without validation. Use relative URLs when possible.',
            'prototype_pollution': 'Avoid using __proto__ or constructor.prototype. Use Object.create(null) for objects. Validate and sanitize all object keys.',
            'regex_dos': 'Avoid nested quantifiers in regex patterns. Test regex with long inputs. Use atomic groups or possessive quantifiers. Set timeout limits for regex operations.',
        }
        return recommendations.get(category, 'Review and fix this security issue according to security best practices.')
    
    def generate_report(self, output_file: str = 'report.html'):
        """Generate an HTML report of findings."""
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 4))
        
        # Count by severity (including dependency findings)
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in self.findings:
            severity_counts[finding['severity']] = severity_counts.get(finding['severity'], 0) + 1
        for dep_finding in self.dependency_findings:
            severity_counts['High'] = severity_counts.get('High', 0) + 1
        
        html_content = self._generate_html(sorted_findings, severity_counts)
        
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] Report generated: {output_path.resolve()}")
    
    def _generate_html(self, findings: List[Dict], severity_counts: Dict) -> str:
        """Generate the HTML report content."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate risk score
        risk_score = min(100,
                        severity_counts.get('Critical', 0) * 10 +
                        severity_counts.get('High', 0) * 5 +
                        severity_counts.get('Medium', 0) * 2 +
                        severity_counts.get('Low', 0) * 1)
        
        # Determine risk level and color
        if risk_score > 70:
            risk_level = 'High Risk'
            risk_color = '#dc3545'
        elif risk_score >= 40:
            risk_level = 'Medium Risk'
            risk_color = '#fd7e14'
        else:
            risk_level = 'Low Risk'
            risk_color = '#28a745'
        
        # Generate findings HTML
        findings_html = ''
        for idx, finding in enumerate(findings, start=1):
            severity_color = {
                'Critical': '#dc3545',
                'High': '#fd7e14',
                'Medium': '#ffc107',
                'Low': '#17a2b8'
            }.get(finding['severity'], '#6c757d')
            
            findings_html += f'''
            <div class="finding-card" data-severity="{finding['severity']}">
                <div class="finding-header">
                    <span class="finding-number">#{idx}</span>
                    <span class="severity-badge" style="background-color: {severity_color};">
                        {finding['severity']}
                    </span>
                </div>
                <h3 class="finding-title">{finding['description']}</h3>
                <div class="finding-details">
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{finding['file']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Line:</span>
                        <span class="detail-value">{finding['line']}</span>
                    </div>
                </div>
                <div class="code-snippet">
                    <div class="code-header">Vulnerable Code:</div>
                    <pre><code>{self._escape_html(finding['code'])}</code></pre>
                </div>
                <div class="recommendation">
                    <div class="recommendation-header">💡 Recommendation:</div>
                    <p>{finding['recommendation']}</p>
                </div>
            </div>
            '''
        
        if not findings_html:
            findings_html = '''
            <div class="no-findings">
                <h2>🎉 No vulnerabilities detected!</h2>
                <p>Your code appears to be free of common security issues.</p>
            </div>
            '''
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeGuard AI - Security Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .header-icon {{
            font-size: 1.2em;
        }}
        
        .header-info {{
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }}
        
        .header-info-item {{
            background: rgba(255, 255, 255, 0.1);
            padding: 10px 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }}
        
        .header-info-label {{
            font-size: 0.85em;
            opacity: 0.9;
            display: block;
        }}
        
        .header-info-value {{
            font-size: 1.1em;
            font-weight: bold;
            color: white;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: #2d2d44;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            border-left: 4px solid;
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card.critical {{
            border-left-color: #dc3545;
        }}
        
        .summary-card.high {{
            border-left-color: #fd7e14;
        }}
        
        .summary-card.medium {{
            border-left-color: #ffc107;
        }}
        
        .summary-card.low {{
            border-left-color: #17a2b8;
        }}
        
        .summary-card h3 {{
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            opacity: 0.8;
        }}
        
        .summary-card .count {{
            font-size: 3em;
            font-weight: bold;
            color: white;
        }}
        
        .findings-section {{
            background: #2d2d44;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .findings-header {{
            font-size: 1.8em;
            margin-bottom: 25px;
            color: white;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .finding-card {{
            background: #1e1e2e;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #3d3d5c;
            transition: all 0.3s;
        }}
        
        .finding-card:hover {{
            border-color: #667eea;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.2);
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .finding-number {{
            font-size: 1.2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            color: white;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .finding-title {{
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #f0f0f0;
        }}
        
        .finding-details {{
            margin-bottom: 15px;
        }}
        
        .detail-row {{
            display: flex;
            gap: 10px;
            margin-bottom: 8px;
        }}
        
        .detail-label {{
            font-weight: bold;
            color: #667eea;
            min-width: 60px;
        }}
        
        .detail-value {{
            color: #b0b0b0;
            font-family: 'Courier New', monospace;
        }}
        
        .code-snippet {{
            background: #0d0d1a;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            border: 1px solid #3d3d5c;
        }}
        
        .code-header {{
            font-size: 0.85em;
            color: #667eea;
            margin-bottom: 10px;
            font-weight: bold;
        }}
        
        .code-snippet pre {{
            margin: 0;
            overflow-x: auto;
        }}
        
        .code-snippet code {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #f8f8f2;
        }}
        
        .recommendation {{
            background: rgba(102, 126, 234, 0.1);
            border-left: 3px solid #667eea;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}
        
        .recommendation-header {{
            font-weight: bold;
            color: #667eea;
            margin-bottom: 8px;
        }}
        
        .recommendation p {{
            color: #d0d0d0;
            font-size: 0.95em;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
        }}
        
        .no-findings h2 {{
            font-size: 2em;
            color: #28a745;
            margin-bottom: 15px;
        }}
        
        .no-findings p {{
            font-size: 1.2em;
            color: #b0b0b0;
        }}
        
        .risk-score-section {{
            background: #2d2d44;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 40px;
            flex-wrap: wrap;
        }}
        
        .risk-gauge {{
            position: relative;
            width: 200px;
            height: 200px;
        }}
        
        .risk-gauge svg {{
            transform: rotate(-90deg);
        }}
        
        .risk-gauge-bg {{
            fill: none;
            stroke: #1e1e2e;
            stroke-width: 20;
        }}
        
        .risk-gauge-fill {{
            fill: none;
            stroke-width: 20;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease;
        }}
        
        .risk-score-text {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }}
        
        .risk-score-number {{
            font-size: 3em;
            font-weight: bold;
            color: white;
        }}
        
        .risk-score-label {{
            font-size: 0.9em;
            color: #b0b0b0;
            margin-top: 5px;
        }}
        
        .risk-info {{
            flex: 1;
            min-width: 300px;
        }}
        
        .risk-level {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 15px;
        }}
        
        .risk-description {{
            color: #b0b0b0;
            line-height: 1.8;
        }}
        
        .filter-bar {{
            background: #2d2d44;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .filter-label {{
            font-weight: bold;
            color: #667eea;
            font-size: 1.1em;
        }}
        
        .filter-btn {{
            padding: 10px 20px;
            border: 2px solid;
            border-radius: 8px;
            background: transparent;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 0.95em;
        }}
        
        .filter-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }}
        
        .filter-btn.active {{
            background: white;
            color: #1e1e2e;
        }}
        
        .filter-btn.all {{
            border-color: #667eea;
        }}
        
        .filter-btn.all.active {{
            background: #667eea;
            color: white;
        }}
        
        .filter-btn.critical {{
            border-color: #dc3545;
        }}
        
        .filter-btn.critical.active {{
            background: #dc3545;
        }}
        
        .filter-btn.high {{
            border-color: #fd7e14;
        }}
        
        .filter-btn.high.active {{
            background: #fd7e14;
        }}
        
        .filter-btn.medium {{
            border-color: #ffc107;
        }}
        
        .filter-btn.medium.active {{
            background: #ffc107;
            color: #1e1e2e;
        }}
        
        .filter-btn.low {{
            border-color: #17a2b8;
        }}
        
        .filter-btn.low.active {{
            background: #17a2b8;
        }}
        
        .finding-card.hidden {{
            display: none;
        }}
        
        .dependency-section {{
            margin-bottom: 30px;
        }}
        
        .section-description {{
            color: #b0b0b0;
            margin-bottom: 20px;
            font-size: 1.05em;
        }}
        
        .dependency-card {{
            border-left: 4px solid #fd7e14;
        }}
        
        .vulnerability-description {{
            background: rgba(253, 126, 20, 0.1);
            border-left: 3px solid #fd7e14;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        
        .vuln-desc-header {{
            font-weight: bold;
            color: #fd7e14;
            margin-bottom: 8px;
        }}
        
        .vulnerability-description p {{
            color: #d0d0d0;
            font-size: 0.95em;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #888;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            
            .summary {{
                grid-template-columns: 1fr;
            }}
            
            .finding-card {{
                padding: 15px;
            }}
            
            .risk-score-section {{
                flex-direction: column;
            }}
            
            .filter-bar {{
                justify-content: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <span class="header-icon">🛡️</span>
                CodeGuard AI Security Report
            </h1>
            <div class="header-info">
                <div class="header-info-item">
                    <span class="header-info-label">Scanned Path</span>
                    <span class="header-info-value">{self.display_path}</span>
                </div>
                <div class="header-info-item">
                    <span class="header-info-label">Scan Date</span>
                    <span class="header-info-value">{timestamp}</span>
                </div>
                <div class="header-info-item">
                    <span class="header-info-label">Files Scanned</span>
                    <span class="header-info-value">{self.files_scanned}</span>
                </div>
                <div class="header-info-item">
                    <span class="header-info-label">Total Findings</span>
                    <span class="header-info-value">{len(findings)}</span>
                </div>
            </div>
        </div>
        
        <div class="risk-score-section">
            <div class="risk-gauge">
                <svg width="200" height="200">
                    <circle class="risk-gauge-bg" cx="100" cy="100" r="90"></circle>
                    <circle class="risk-gauge-fill" cx="100" cy="100" r="90"
                            style="stroke: {risk_color}; stroke-dasharray: 565.48; stroke-dashoffset: {565.48 * (1 - risk_score / 100)};">
                    </circle>
                </svg>
                <div class="risk-score-text">
                    <div class="risk-score-number">{risk_score}</div>
                    <div class="risk-score-label">Risk Score</div>
                </div>
            </div>
            <div class="risk-info">
                <div class="risk-level" style="color: {risk_color};">{risk_level}</div>
                <div class="risk-description">
                    <p><strong>Score Calculation:</strong> Critical (×10) + High (×5) + Medium (×2) + Low (×1)</p>
                    <p><strong>Total Issues:</strong> {len(findings)} vulnerabilities detected across {self.files_scanned} files</p>
                    <p><strong>Recommendation:</strong> {'Immediate action required! Address critical and high severity issues first.' if risk_score > 70 else 'Review and fix identified issues to improve security posture.' if risk_score >= 40 else 'Good security posture. Continue monitoring and maintaining best practices.'}</p>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="count">{severity_counts.get('Critical', 0)}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="count">{severity_counts.get('High', 0)}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="count">{severity_counts.get('Medium', 0)}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="count">{severity_counts.get('Low', 0)}</div>
            </div>
        </div>
        
        <div class="filter-bar">
            <span class="filter-label">Filter by Severity:</span>
            <button class="filter-btn all active" onclick="filterFindings('all')">All ({len(findings)})</button>
            <button class="filter-btn critical" onclick="filterFindings('Critical')">Critical ({severity_counts.get('Critical', 0)})</button>
            <button class="filter-btn high" onclick="filterFindings('High')">High ({severity_counts.get('High', 0)})</button>
            <button class="filter-btn medium" onclick="filterFindings('Medium')">Medium ({severity_counts.get('Medium', 0)})</button>
            <button class="filter-btn low" onclick="filterFindings('Low')">Low ({severity_counts.get('Low', 0)})</button>
        </div>
        
        {self._generate_dependency_section()}
        
        <div class="findings-section">
            <h2 class="findings-header">🔍 Code Vulnerability Findings</h2>
            {findings_html}
        </div>
        
        <div class="footer">
            <p>Generated by CodeGuard AI - Security Vulnerability Scanner</p>
            <p>⚠️ This report is for informational purposes. Always verify findings and follow security best practices.</p>
        </div>
    </div>
    
    <script>
        function filterFindings(severity) {{
            const cards = document.querySelectorAll('.finding-card');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update button states
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter cards
            cards.forEach(card => {{
                if (severity === 'all') {{
                    card.classList.remove('hidden');
                }} else {{
                    if (card.dataset.severity === severity) {{
                        card.classList.remove('hidden');
                    }} else {{
                        card.classList.add('hidden');
                    }}
                }}
            }});
        }}
    </script>
</body>
</html>'''
        return html
    
    def _generate_dependency_section(self) -> str:
        """Generate HTML for dependency vulnerabilities section."""
        if not self.dependency_findings:
            return ''
        
        dep_html = '''
        <div class="findings-section dependency-section">
            <h2 class="findings-header">📦 Dependency Vulnerabilities</h2>
            <p class="section-description">Vulnerable package versions detected in your dependencies</p>
        '''
        
        for idx, dep in enumerate(self.dependency_findings, start=1):
            dep_html += f'''
            <div class="finding-card dependency-card" data-severity="High">
                <div class="finding-header">
                    <span class="finding-number">DEP-{idx}</span>
                    <span class="severity-badge" style="background-color: #fd7e14;">
                        High
                    </span>
                </div>
                <h3 class="finding-title">Vulnerable Package: {dep['package']}</h3>
                <div class="finding-details">
                    <div class="detail-row">
                        <span class="detail-label">Package:</span>
                        <span class="detail-value">{dep['package']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Current Version:</span>
                        <span class="detail-value" style="color: #dc3545;">{dep['version']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Min Safe Version:</span>
                        <span class="detail-value" style="color: #28a745;">{dep['min_safe_version']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{dep['file']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">CVE:</span>
                        <span class="detail-value">{dep['cve']}</span>
                    </div>
                </div>
                <div class="vulnerability-description">
                    <div class="vuln-desc-header">⚠️ Vulnerability:</div>
                    <p>{dep['description']}</p>
                </div>
                <div class="recommendation">
                    <div class="recommendation-header">💡 Fix:</div>
                    <p>Upgrade <strong>{dep['package']}</strong> to version <strong>{dep['min_safe_version']}</strong> or higher.</p>
                    <p><code>npm install {dep['package']}@{dep['min_safe_version']}</code> or <code>pip install {dep['package']}>={dep['min_safe_version']}</code></p>
                </div>
            </div>
            '''
        
        dep_html += '</div>'
        return dep_html
    
    def export_json(self, output_file: str = 'report.json'):
        """Export findings to JSON format."""
        export_data = {
            'scan_info': {
                'target_path': self.display_path,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'files_scanned': self.files_scanned
            },
            'summary': {
                'total_findings': len(self.findings) + len(self.dependency_findings),
                'code_findings': len(self.findings),
                'dependency_findings': len(self.dependency_findings)
            },
            'code_vulnerabilities': self.findings,
            'dependency_vulnerabilities': self.dependency_findings
        }
        
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON export generated: {output_path.resolve()}")
    
    def export_csv(self, output_file: str = 'report.csv'):
        """Export findings to CSV format."""
        import csv
        
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Severity', 'Description', 'File', 'Line', 'Code Snippet', 'Recommendation'])
            
            # Write code findings
            for finding in self.findings:
                writer.writerow([
                    'Code',
                    finding['severity'],
                    finding['description'],
                    finding['file'],
                    finding['line'],
                    finding['code'],
                    finding['recommendation']
                ])
            
            # Write dependency findings
            for dep in self.dependency_findings:
                writer.writerow([
                    'Dependency',
                    dep['severity'],
                    f"Vulnerable package: {dep['package']} (CVE: {dep['cve']})",
                    dep['file'],
                    'N/A',
                    f"{dep['package']} {dep['version']} (min safe: {dep['min_safe_version']})",
                    f"Upgrade {dep['package']} to version {dep['min_safe_version']} or higher"
                ])
        
        print(f"[+] CSV export generated: {output_path.resolve()}")
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        text = text.replace('&', '&' + 'amp;')
        text = text.replace('<', '&' + 'lt;')
        text = text.replace('>', '&' + 'gt;')
        text = text.replace('"', '&' + 'quot;')
        text = text.replace("'", '&' + '#39;')
        return text

class WebSecurityAnalyzer:
    """Analyzer for web application security checks."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings: List[Dict] = []
        self.scan_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Import required modules
        import urllib.request
        import urllib.parse
        import urllib.error
        import ssl
        import http.client
        from datetime import timedelta
        
        self.urllib_request = urllib.request
        self.urllib_parse = urllib.parse
        self.urllib_error = urllib.error
        self.ssl_module = ssl
        self.http_client = http.client
        self.timedelta = timedelta
    
    def analyze(self) -> List[Dict]:
        """Run all web security checks."""
        print(f"[*] Starting web security analysis of: {self.target_url}")
        print(f"[*] Timestamp: {self.scan_timestamp}")
        print()
        
        # Parse URL to check if it's HTTP or HTTPS
        parsed_url = self.urllib_parse.urlparse(self.target_url)
        
        if parsed_url.scheme == 'http':
            self.findings.append({
                'category': 'ssl_tls',
                'severity': 'Critical',
                'description': 'Website uses insecure HTTP protocol',
                'details': 'The website is not using HTTPS encryption',
                'recommendation': 'Enable HTTPS with a valid SSL/TLS certificate to encrypt data in transit'
            })
        
        # Run all checks
        self._check_security_headers()
        if parsed_url.scheme == 'https':
            self._check_ssl_certificate()
        self._check_exposed_files()
        self._check_cookies()
        self._scan_javascript_secrets()
        
        print(f"[*] Web security analysis complete")
        print(f"[*] Total findings: {len(self.findings)}")
        print()
        
        return self.findings
    
    def _make_request(self, url: str, method: str = 'GET', timeout: int = 10) -> Tuple[Optional[object], Optional[Dict]]:
        """Make HTTP request and return response object and headers."""
        try:
            req = self.urllib_request.Request(url, method=method)
            req.add_header('User-Agent', 'CodeGuard-AI-Scanner/1.0')
            
            # Create SSL context that doesn't verify certificates (for testing purposes)
            context = self.ssl_module.create_default_context()
            context.check_hostname = False
            context.verify_mode = self.ssl_module.CERT_NONE
            
            response = self.urllib_request.urlopen(req, timeout=timeout, context=context)
            headers = dict(response.headers)
            return response, headers
        except self.urllib_error.HTTPError as e:
            # Return error response for status code checking
            return e, dict(e.headers) if hasattr(e, 'headers') else {}
        except Exception as e:
            print(f"[!] Request error for {url}: {e}")
            return None, {}
    
    def _check_security_headers(self):
        """Check for missing security headers."""
        print("[*] Checking security headers...")
        
        response, headers = self._make_request(self.target_url)
        if not headers:
            return
        
        # Convert header keys to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check Content-Security-Policy
        if 'content-security-policy' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'High',
                'description': 'Missing Content-Security-Policy header',
                'details': 'CSP header not found in response',
                'recommendation': 'Add Content-Security-Policy header to prevent XSS and data injection attacks'
            })
        
        # Check HSTS
        if 'strict-transport-security' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'High',
                'description': 'Missing Strict-Transport-Security (HSTS) header',
                'details': 'HSTS header not found in response',
                'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS connections'
            })
        
        # Check X-Frame-Options
        if 'x-frame-options' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'Medium',
                'description': 'Missing X-Frame-Options header',
                'details': 'X-Frame-Options header not found in response',
                'recommendation': 'Add X-Frame-Options header to prevent clickjacking attacks'
            })
        
        # Check X-Content-Type-Options
        if 'x-content-type-options' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'Medium',
                'description': 'Missing X-Content-Type-Options header',
                'details': 'X-Content-Type-Options header not found in response',
                'recommendation': 'Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing'
            })
        
        # Check X-XSS-Protection
        if 'x-xss-protection' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'Medium',
                'description': 'Missing X-XSS-Protection header',
                'details': 'X-XSS-Protection header not found in response',
                'recommendation': 'Add X-XSS-Protection: 1; mode=block header for legacy browser protection'
            })
        
        # Check Referrer-Policy
        if 'referrer-policy' not in headers_lower:
            self.findings.append({
                'category': 'security_headers',
                'severity': 'Low',
                'description': 'Missing Referrer-Policy header',
                'details': 'Referrer-Policy header not found in response',
                'recommendation': 'Add Referrer-Policy header to control referrer information leakage'
            })
        
        print(f"[+] Security headers check complete")
    
    def _check_ssl_certificate(self):
        """Check SSL/TLS certificate validity and expiration."""
        print("[*] Checking SSL/TLS certificate...")
        
        try:
            import socket
            parsed_url = self.urllib_parse.urlparse(self.target_url)
            hostname = parsed_url.netloc
            port = 443
            
            # Create SSL context
            context = self.ssl_module.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    if cert and 'notAfter' in cert:
                        not_after = cert['notAfter']
                        # Parse certificate expiry date
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            self.findings.append({
                                'category': 'ssl_tls',
                                'severity': 'Critical',
                                'description': 'SSL/TLS certificate has expired',
                                'details': f'Certificate expired on {not_after}',
                                'recommendation': 'Renew the SSL/TLS certificate immediately'
                            })
                        elif days_until_expiry <= 30:
                            self.findings.append({
                                'category': 'ssl_tls',
                                'severity': 'Medium',
                                'description': 'SSL/TLS certificate expiring soon',
                                'details': f'Certificate expires in {days_until_expiry} days on {not_after}',
                                'recommendation': 'Renew the SSL/TLS certificate before it expires'
                            })
            
            print(f"[+] SSL/TLS certificate check complete")
        
        except self.ssl_module.SSLError as e:
            self.findings.append({
                'category': 'ssl_tls',
                'severity': 'Critical',
                'description': 'SSL/TLS certificate validation failed',
                'details': f'SSL Error: {str(e)}',
                'recommendation': 'Fix SSL/TLS certificate issues (invalid, self-signed, or expired)'
            })
            print(f"[!] SSL/TLS error: {e}")
        except Exception as e:
            print(f"[!] Certificate check error: {e}")
    
    def _check_exposed_files(self):
        """Check for exposed sensitive files."""
        print("[*] Checking for exposed sensitive files...")
        
        sensitive_paths = [
            '/.env',
            '/config.json',
            '/wp-config.php',
            '/phpinfo.php',
            '/.git/config',
            '/backup.sql',
            '/admin',
            '/api/v1/users'
        ]
        
        parsed_url = self.urllib_parse.urlparse(self.target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in sensitive_paths:
            try:
                url = base_url + path
                response, headers = self._make_request(url)
                
                if response and hasattr(response, 'code') and response.code == 200:
                    self.findings.append({
                        'category': 'exposed_files',
                        'severity': 'High',
                        'description': f'Sensitive file exposed: {path}',
                        'details': f'File accessible at {url} (HTTP 200)',
                        'recommendation': f'Restrict access to {path} or remove it from the web root'
                    })
            except:
                # File not accessible, which is good
                pass
        
        print(f"[+] Exposed files check complete")
    
    def _check_cookies(self):
        """Check cookie security attributes."""
        print("[*] Checking cookie security...")
        
        response, headers = self._make_request(self.target_url)
        if not headers:
            return
        
        # Get all Set-Cookie headers
        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
        
        if not set_cookie_headers:
            return
        
        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split('=')[0] if '=' in cookie_header else 'unknown'
            
            # Check for Secure flag
            if 'secure' not in cookie_lower:
                self.findings.append({
                    'category': 'cookie_security',
                    'severity': 'High',
                    'description': f'Cookie missing Secure flag: {cookie_name}',
                    'details': 'Cookie can be transmitted over insecure HTTP connections',
                    'recommendation': 'Add Secure flag to ensure cookie is only sent over HTTPS'
                })
            
            # Check for HttpOnly flag
            if 'httponly' not in cookie_lower:
                self.findings.append({
                    'category': 'cookie_security',
                    'severity': 'High',
                    'description': f'Cookie missing HttpOnly flag: {cookie_name}',
                    'details': 'Cookie accessible via JavaScript, vulnerable to XSS attacks',
                    'recommendation': 'Add HttpOnly flag to prevent JavaScript access to the cookie'
                })
            
            # Check for SameSite attribute
            if 'samesite' not in cookie_lower:
                self.findings.append({
                    'category': 'cookie_security',
                    'severity': 'Medium',
                    'description': f'Cookie missing SameSite attribute: {cookie_name}',
                    'details': 'Cookie vulnerable to CSRF attacks',
                    'recommendation': 'Add SameSite attribute (Strict or Lax) to prevent CSRF attacks'
                })
        
        print(f"[+] Cookie security check complete")
    
    def _scan_javascript_secrets(self):
        """Scan JavaScript files for hardcoded secrets."""
        print("[*] Scanning JavaScript files for secrets...")
        
        try:
            # Fetch the main page
            response, headers = self._make_request(self.target_url)
            if not response:
                return
            
            html_content = response.read().decode('utf-8', errors='ignore')
            
            # Extract script src URLs
            script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
            script_urls = re.findall(script_pattern, html_content, re.IGNORECASE)
            
            parsed_url = self.urllib_parse.urlparse(self.target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Limit to first 10 scripts to avoid excessive requests
            for script_url in script_urls[:10]:
                # Handle relative URLs
                if script_url.startswith('//'):
                    script_url = parsed_url.scheme + ':' + script_url
                elif script_url.startswith('/'):
                    script_url = base_url + script_url
                elif not script_url.startswith('http'):
                    continue
                
                try:
                    js_response, js_headers = self._make_request(script_url)
                    if not js_response:
                        continue
                    
                    js_content = js_response.read().decode('utf-8', errors='ignore')
                    
                    # Use existing secret patterns from VulnerabilityScanner
                    secret_patterns = [
                        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                         'API key found in JavaScript'),
                        (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                         'Secret key found in JavaScript'),
                        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']',
                         'Password found in JavaScript'),
                        (r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
                         'Auth token found in JavaScript'),
                        (r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})',
                         'JWT token found in JavaScript'),
                    ]
                    
                    for pattern, description in secret_patterns:
                        matches = re.finditer(pattern, js_content)
                        for match in matches:
                            # Get context around the match
                            start = max(0, match.start() - 50)
                            end = min(len(js_content), match.end() + 50)
                            context = js_content[start:end].strip()
                            
                            self.findings.append({
                                'category': 'javascript_secrets',
                                'severity': 'Critical',
                                'description': description,
                                'details': f'Found in {script_url}',
                                'code': context[:100],
                                'recommendation': 'Remove hardcoded secrets from JavaScript files. Use environment variables or secure configuration management.'
                            })
                
                except Exception as e:
                    continue
            
            print(f"[+] JavaScript secret scanning complete")
        
        except Exception as e:
            print(f"[!] JavaScript scanning error: {e}")



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
    
    print(f"[*] Cloning repository: {repo_url}")
    print(f"[*] Temporary directory: {temp_dir}")
    
    try:
        # Clone the repository
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            print(f"[!] Error cloning repository: {result.stderr}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.exit(1)
        
        print(f"[+] Repository cloned successfully")
        return temp_dir, repo_url
    
    except subprocess.TimeoutExpired:
        print("[!] Error: Clone operation timed out (5 minutes)")
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
    except FileNotFoundError:
        print("[!] Error: git command not found. Please install git.")
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)



def generate_web_report(analyzer: WebSecurityAnalyzer, findings: List[Dict], severity_counts: Dict, output_path: Path):
    """Generate HTML report for web security analysis."""
    
    # Group findings by category
    findings_by_category = {}
    for finding in findings:
        category = finding['category']
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)
    
    # Calculate risk score
    risk_score = min(100, severity_counts['Critical'] * 10 + severity_counts['High'] * 5 + 
                     severity_counts['Medium'] * 2 + severity_counts['Low'] * 1)
    
    # Severity colors
    severity_colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#17a2b8'
    }
    
    # Category display names
    category_names = {
        'security_headers': 'Security Headers',
        'ssl_tls': 'SSL/TLS Certificate',
        'exposed_files': 'Exposed Sensitive Files',
        'cookie_security': 'Cookie Security',
        'javascript_secrets': 'JavaScript Secrets'
    }
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeGuard AI - Web Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #1a1a2e;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            color: white;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        .target-url {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            word-break: break-all;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #16213e;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #2d3561 0%, #1f2544 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid rgba(255,255,255,0.1);
            transition: transform 0.3s ease;
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        .summary-card .count {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .summary-card .label {{
            color: #a0a0a0;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .risk-score {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            padding: 30px;
            text-align: center;
            color: white;
        }}
        .risk-score .score {{
            font-size: 4em;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .risk-score .label {{
            font-size: 1.2em;
            margin-top: 10px;
        }}
        .content {{
            padding: 40px;
        }}
        .category-section {{
            margin-bottom: 40px;
        }}
        .category-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .finding-card {{
            background: #16213e;
            border-left: 4px solid;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            transition: transform 0.2s ease;
        }}
        .finding-card:hover {{
            transform: translateX(5px);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .finding-description {{
            color: #e0e0e0;
            font-size: 1.1em;
            margin-bottom: 10px;
        }}
        .finding-details {{
            color: #a0a0a0;
            margin-bottom: 15px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
        }}
        .finding-code {{
            background: #0d1117;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #58a6ff;
            overflow-x: auto;
            margin-bottom: 15px;
        }}
        .recommendation {{
            background: rgba(102, 126, 234, 0.1);
            border-left: 3px solid #667eea;
            padding: 15px;
            border-radius: 5px;
            color: #b0b0b0;
        }}
        .recommendation strong {{
            color: #667eea;
        }}
        .footer {{
            background: #0f0f1e;
            padding: 30px;
            text-align: center;
            color: #666;
        }}
        .timestamp {{
            color: #888;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 CodeGuard AI</h1>
            <div class="subtitle">Web Security Analysis Report</div>
            <div class="target-url">
                <strong>Target:</strong> {analyzer.target_url}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="label">Critical</div>
                <div class="count" style="color: {severity_colors['Critical']}">{severity_counts['Critical']}</div>
            </div>
            <div class="summary-card">
                <div class="label">High</div>
                <div class="count" style="color: {severity_colors['High']}">{severity_counts['High']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Medium</div>
                <div class="count" style="color: {severity_colors['Medium']}">{severity_counts['Medium']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Low</div>
                <div class="count" style="color: {severity_colors['Low']}">{severity_counts['Low']}</div>
            </div>
        </div>
        
        <div class="risk-score">
            <div class="score">{risk_score}/100</div>
            <div class="label">Security Risk Score</div>
        </div>
        
        <div class="content">
'''
    
    # Add findings by category
    for category, category_findings in findings_by_category.items():
        category_name = category_names.get(category, category.replace('_', ' ').title())
        html_content += f'''
            <div class="category-section">
                <div class="category-header">{category_name}</div>
'''
        
        for finding in category_findings:
            severity = finding['severity']
            color = severity_colors[severity]
            
            html_content += f'''
                <div class="finding-card" style="border-left-color: {color}">
                    <div class="finding-header">
                        <div class="finding-description">{finding['description']}</div>
                        <span class="severity-badge" style="background-color: {color}; color: white;">{severity}</span>
                    </div>
                    <div class="finding-details">{finding['details']}</div>
'''
            
            if 'code' in finding:
                escaped_code = finding['code'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                html_content += f'''
                    <div class="finding-code">{escaped_code}</div>
'''
            
            html_content += f'''
                    <div class="recommendation">
                        <strong>💡 Recommendation:</strong> {finding['recommendation']}
                    </div>
                </div>
'''
        
        html_content += '''
            </div>
'''
    
    html_content += f'''
        </div>
        
        <div class="footer">
            <div class="timestamp">
                Report generated on {analyzer.scan_timestamp}
            </div>
            <div style="margin-top: 10px;">
                Powered by <strong>CodeGuard AI</strong>
            </div>
        </div>
    </div>
</body>
</html>
'''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python codeguard.py <folder_path_or_github_url> [--export json|csv] [--ci]")
        print("       python codeguard.py --web <url>")
        print("Examples:")
        print("  python codeguard.py ./my-project")
        print("  python codeguard.py https://github.com/user/repo")
        print("  python codeguard.py ./my-project --export json")
        print("  python codeguard.py https://github.com/user/repo --export csv")
        print("  python codeguard.py . --ci  # CI/CD mode")
        print("  python codeguard.py --web https://example.com")
        sys.exit(1)
    
    # Check for --web flag
    web_mode = '--web' in sys.argv
    
    if web_mode:
        # Web security analysis mode
        if '--web' in sys.argv:
            web_idx = sys.argv.index('--web')
            if web_idx + 1 < len(sys.argv):
                target_url = sys.argv[web_idx + 1]
            else:
                print("[!] Error: --web flag requires a URL argument")
                sys.exit(1)
        
        print("=" * 60)
        print("  CodeGuard AI - Web Security Analyzer")
        print("=" * 60)
        print()
        
        try:
            analyzer = WebSecurityAnalyzer(target_url)
            web_findings = analyzer.analyze()
            
            # Calculate severity counts
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in web_findings:
                severity_counts[finding['severity']] = severity_counts.get(finding['severity'], 0) + 1
            
            # Generate report
            print("=" * 60)
            print("  Generating Report...")
            print("=" * 60)
            print()
            
            output_path = Path('report.html')
            generate_web_report(analyzer, web_findings, severity_counts, output_path)
            
            print(f"[+] Report generated: {output_path.resolve()}")
            print()
            print("=" * 60)
            print("  Scan Summary")
            print("=" * 60)
            print(f"  Critical: {severity_counts['Critical']}")
            print(f"  High:     {severity_counts['High']}")
            print(f"  Medium:   {severity_counts['Medium']}")
            print(f"  Low:      {severity_counts['Low']}")
            print(f"  Total:    {sum(severity_counts.values())}")
            print("=" * 60)
            print()
            print("[✓] Done! Open report.html in your browser to view the results.")
            
        except Exception as e:
            print(f"[!] Error during web analysis: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
        return
    
    # Original code scanning mode
    target_input = sys.argv[1]
    temp_dir = None
    display_path = target_input
    export_format = None
    ci_mode = '--ci' in sys.argv
    
    # Check for --export flag
    if '--export' in sys.argv:
        export_idx = sys.argv.index('--export')
        if export_idx + 1 < len(sys.argv):
            export_format = sys.argv[export_idx + 1].lower()
            if export_format not in ['json', 'csv']:
                print(f"[!] Error: Invalid export format '{sys.argv[export_idx + 1]}'. Use 'json' or 'csv'.")
                sys.exit(1)
    
    if not ci_mode:
        print("=" * 60)
        print("  CodeGuard AI - Security Vulnerability Scanner")
        print("=" * 60)
        print()
    
    # Check if input is a GitHub URL
    if is_github_url(target_input):
        temp_dir, display_path = clone_github_repo(target_input)
        target_path = temp_dir
        print()
    else:
        target_path = target_input
    
    try:
        scanner = VulnerabilityScanner(target_path, display_path)
        findings = scanner.scan()
        
        # Calculate severity counts
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in findings:
            severity_counts[finding['severity']] = severity_counts.get(finding['severity'], 0) + 1
        # Add dependency findings to High count
        severity_counts['High'] += len(scanner.dependency_findings)
        
        if ci_mode:
            # CI mode: Print JSON summary and exit with appropriate code
            ci_summary = {
                'status': 'fail' if (severity_counts['Critical'] > 0 or severity_counts['High'] > 0) else 'pass',
                'scan_info': {
                    'target': display_path,
                    'files_scanned': scanner.files_scanned,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                },
                'severity_counts': severity_counts,
                'total_findings': len(findings) + len(scanner.dependency_findings),
                'critical_or_high': severity_counts['Critical'] + severity_counts['High']
            }
            
            print(json.dumps(ci_summary, indent=2))
            
            # Exit with code 1 if Critical or High findings exist
            if severity_counts['Critical'] > 0 or severity_counts['High'] > 0:
                sys.exit(1)
            else:
                sys.exit(0)
        
        else:
            # Normal mode: Generate reports
            print()
            print("=" * 60)
            print("  Generating Reports...")
            print("=" * 60)
            print()
            
            # Always generate HTML report
            scanner.generate_report('report.html')
            
            # Generate additional export if requested
            if export_format == 'json':
                scanner.export_json('report.json')
            elif export_format == 'csv':
                scanner.export_csv('report.csv')
            
            print()
            print("=" * 60)
            print("  Scan Summary")
            print("=" * 60)
            
            print(f"  Critical: {severity_counts['Critical']}")
            print(f"  High:     {severity_counts['High']}")
            print(f"  Medium:   {severity_counts['Medium']}")
            print(f"  Low:      {severity_counts['Low']}")
            print(f"  Total:    {len(findings) + len(scanner.dependency_findings)}")
            print("=" * 60)
            print()
            print("[✓] Done! Open report.html in your browser to view the results.")
            if export_format:
                print(f"[✓] {export_format.upper()} export saved to report.{export_format}")
    
    finally:
        # Clean up temporary directory if it was created
        if temp_dir and os.path.exists(temp_dir):
            print()
            print("[*] Cleaning up temporary directory...")
            shutil.rmtree(temp_dir, ignore_errors=True)
            print("[+] Cleanup complete")


if __name__ == '__main__':
    main()
