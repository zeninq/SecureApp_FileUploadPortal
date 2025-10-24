# Security Testing Report: SecureApp File Upload Portal

This report summarizes the results of three automated security testing approaches — SAST (Static Analysis), DAST (Dynamic Analysis), and SCA (Dependency Vulnerability Scanning) — performed on the SecureApp File Upload Portal Flask application.

## 1. Tools Used

| Test Type | Tool | Description | Execution Command |
|-----------|------|-------------|-------------------|
| SAST | Bandit | Static code analyzer for Python detecting common security issues | `bandit -r flaskup/ -f html -o reports/bandit_report.html` |
| DAST | OWASP ZAP (Docker) | Dynamic web application security scanner for runtime vulnerabilities | `docker run --rm -v ${PWD}/reports:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000 -r zap_baseline_report.html` |
| SCA | pip-audit | Python package vulnerability scanner | `pip-audit` |

## 2. SAST Results (Static Application Security Testing – Bandit)

**Tool:** Bandit  
**Scan Target:** flaskup/ directory  
**Lines of Code:** 581  
**Findings:** 10 security issues

### Key Findings

| Issue | Severity | CWE | File | Line | Description |
|-------|----------|-----|------|------|-------------|
| Hardcoded temp directory (/tmp/flaskup) | Medium | CWE-377 | \_\_init\_\_.py | 16 | Temporary directory may allow unauthorized file access |
| Use of assert statements for validation | Low | CWE-703 | \_\_init\_\_.py | 51–65 | Asserts can be disabled in production, bypassing checks |
| Hardcoded password string 'admin123' | Low | CWE-259 | views.py | 41 | Hardcoded credentials can be leaked or exploited |
| Multiple try/except/pass blocks | Low | CWE-703 | models.py, utils.py, views.py | Various | Exceptions are silently ignored, hiding possible failures |

### CVSS-Based Risk Analysis (Estimated)

| Vulnerability | CVSS 3.1 Base Score | Risk Level |
|---------------|---------------------|------------|
| Hardcoded temp directory | 6.1 | Medium |
| Use of assert | 3.1 | Low |
| Hardcoded credentials | 5.3 | Medium |
| Silent exception handling | 4.0 | Low |

### Suggested Fixes

- Replace `/tmp/flaskup` with a secure app data directory (e.g., `/var/lib/flaskup/uploads` or `os.path.join(tempfile.gettempdir(), 'flaskup')`)
- Replace all assert statements with explicit exception handling
- Move credentials to environment variables or secure configuration files
- Replace empty except blocks with logging and proper error handling

## 3. DAST Results (Dynamic Application Security Testing – OWASP ZAP)

**Tool:** OWASP ZAP by Checkmarx (Docker version)  
**Target URL:** http://host.docker.internal:5000  
**ZAP Version:** 2.16.1

### Summary of Alerts

| Risk Level | Number of Alerts |
|------------|------------------|
| High | 0 |
| Medium | 4 |
| Low | 2 |
| Informational | 5 |

### Medium Severity Issues

| Issue | CWE | Description | Suggested Fix |
|-------|-----|-------------|---------------|
| Absence of Anti-CSRF Tokens | CWE-352 | No CSRF protection detected on login form | Implement CSRF tokens using Flask-WTF or itsdangerous |
| CSP: Missing frame-ancestors & form-action directives | CWE-693 | Incomplete Content-Security-Policy headers | Add full CSP directives including frame-ancestors 'none' |
| CSP: script-src includes unsafe-inline | CWE-693 | Allows inline scripts, increasing XSS risk | Remove 'unsafe-inline' and use nonce-based CSP |
| CSP: style-src includes unsafe-inline | CWE-693 | Allows inline styles | Use hashed styles or external CSS only |

### Low Severity Issues

| Issue | CWE | Description | Suggested Fix |
|-------|-----|-------------|---------------|
| Server Leaks Version Info via HTTP Header | CWE-497 | Werkzeug/3.1.3 Python/3.12.5 exposed | Suppress Server header using a proxy or WSGI middleware |
| Insufficient Site Isolation (Spectre) | CWE-693 | Missing Cross-Origin-Resource-Policy headers | Add Cross-Origin-Resource-Policy: same-origin |

### CVSS-Based Risk Analysis (Estimated)

| Vulnerability | CVSS 3.1 Base Score | Risk Level |
|---------------|---------------------|------------|
| Missing CSRF protection | 6.8 | Medium |
| CSP misconfiguration | 6.5 | Medium |
| Server header exposure | 3.7 | Low |
| Missing site isolation headers | 3.5 | Low |

### Suggested Fixes

**Enable CSRF Protection:**
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```
**Harden CSP Policy with Flask-Talisman:**
```python
from flask_talisman import Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self' https://cdn.jsdelivr.net",
    'style-src': "'self' https://cdn.jsdelivr.net",
    'frame-ancestors': "'none'",
    'form-action': "'self'"
})
```
**Suppress version headers:**
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app, x_proto=1)
```
**Add cross-origin protection headers:**
```python
@app.after_request
def set_headers(response):
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response
```

## 4. SCA Results (Software Composition Analysis – pip-audit)

**Tool:** pip-audit  
**Findings:** 1 vulnerable dependency

| Package | Version | Vulnerability ID | Fixed Version | Description |
|---------|---------|------------------|---------------|-------------|
| flask | 1.1.1 | PYSEC-2023-62 | 2.2.5 / 2.3.2 | Flask 1.1.1 allows bypassing debugging restrictions leading to potential RCE |

### CVSS-Based Risk Analysis (Estimated)

| Vulnerability | CVSS 3.1 Base Score | Risk Level |
|---------------|---------------------|------------|
| Flask (PYSEC-2023-62) | 8.6 | High |

### Suggested Fix

Upgrade Flask to a patched version:
```bash
pip install --upgrade flask==2.3.2
```
Re-run pip-audit to verify no remaining vulnerabilities.

## 5. Overall Summary

| Test Type | Tool | Risk Level | Key Findings |
|-----------|------|------------|--------------|
| SAST | Bandit | Medium | Hardcoded password and temp path issues |
| DAST | OWASP ZAP | Medium | Missing CSRF protection, weak CSP |
| SCA | pip-audit | High | Vulnerable Flask dependency |