# GitGuard

> A lightweight DevSecOps secret detection and prevention tool for detecting exposed credentials before they reach version control and CI/CD pipelines.

GitGuard scans source code for potentially exposed secrets using pattern-based detection, context-aware filtering, and entropy analysis. It integrates directly with Git through pre-commit hooks and GitHub Actions, providing both local prevention and CI/CD enforcement.

Detected findings can also be exported in SARIF format and uploaded to GitHub Code Scanning for centralized security visibility.

---

## Features

### 🔐 Secret Detection

GitGuard detects several common categories of sensitive information:

- AWS access keys
- Private keys
- JWT tokens
- Hardcoded passwords
- High-entropy secrets
- Other configurable secret patterns

### 🧠 Context-Aware Detection

Not every string resembling a secret is actually a secret.

GitGuard applies contextual checks to reduce false positives, including filtering common placeholders and non-sensitive values.

### 📊 Entropy Analysis

GitGuard calculates Shannon entropy to identify strings with high randomness that may represent previously unknown or unrecognized secrets.

Example:

```text
aaaaaaaaaaaaaaaa     → low entropy
abcdefghijklmnop     → high entropy
random credential    → high entropy
```

This provides an additional detection layer beyond fixed regular expressions.

### 🗂️ Git History Scanning

Secrets can remain exposed in previous commits even after being removed from the latest version of a file.

GitGuard can scan Git history to identify historical secret exposure.

```bash
gitguard history .
```

### 🛡️ Pre-Commit Protection

GitGuard integrates with Git pre-commit hooks and scans the **staged version of files** before a commit is created.

```text
git add
   ↓
Staging Area
   ↓
git commit
   ↓
GitGuard
   ↓
Secret detected?
   ├── YES → ❌ Block commit
   └── NO  → ✅ Allow commit
```

This prevents accidental secrets from entering the repository.

### ⚙️ GitHub Actions CI

GitGuard can run automatically on:

- Pushes
- Pull requests

```text
Developer
    ↓
git push
    ↓
GitHub Actions
    ↓
GitGuard
    ↓
Security scan
    ↓
PASS / FAIL
```

A non-zero exit code causes the CI job to fail when secrets are detected.

### 📋 SARIF Reporting

GitGuard generates SARIF 2.1.0 reports for integration with GitHub Code Scanning.

```text
GitGuard
    ↓
SARIF
    ↓
GitHub Code Scanning
    ↓
Security findings
```

Findings include:

- Rule / secret type
- Severity
- Confidence
- File location
- Line number
- Detection message

Secret values themselves are never included in reports.

### 📄 JSON Reporting

GitGuard can also produce machine-readable JSON output:

```bash
gitguard scan . --format json
```

This allows the scanner to be integrated with other scripts and automation.

### 🔒 Secret Redaction

GitGuard does not expose detected secret values in terminal, JSON, or SARIF reports.

Example:

```text
[CRITICAL] config.py:18
  Type: AWS Access Key
  Confidence: HIGH
```

The actual credential is never printed.

---

# Architecture

```text
                              GitGuard
                                 │
                   ┌─────────────┴────────────┐
                   │                          │
              Local Usage                 CI/CD Usage
                   │                          │
        ┌──────────┼──────────┐         GitHub Actions
        │          │          │               │
        ▼          ▼          ▼               │
   Repository  Pre-Commit  Git History        │
      Scan        Hook        Scan            │
        │          │          │               │
        │     Staged Files    │               │
        │          │          │               │
        └──────────┴──────────┴───────┬───────┘
                                      ▼
                              Detection Engine
                                      │
                       ┌──────────────┼──────────────┐
                       ▼              ▼              ▼
                    Regex          Context        Entropy
                  Detection        Filtering       Analysis
                       └──────────────┼──────────────┘
                                      ▼
                              Finding Aggregation
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                    Terminal                 Reporting
                     Output                 ┌──────┴──────┐
                                           ▼             ▼
                                         JSON          SARIF
                                                         │
                                                         ▼
                                               GitHub Code Scanning
```

---

# Detection Pipeline

GitGuard processes repository content through multiple detection layers:

```text
Source File
    ↓
File Filtering
    ↓
Pattern Detection
    ↓
Context Filtering
    ↓
Entropy Analysis
    ↓
Finding Aggregation
    ↓
Severity / Confidence
    ↓
Report
```

The detector architecture is designed so that detection logic is separated from reporting and Git integration.

This allows the same detection engine to be reused by:

- CLI scanning
- Pre-commit hooks
- Git history scanning
- GitHub Actions
- JSON reporting
- SARIF reporting

---

# Installation

## Requirements

- Python 3.10+
- Git
- GitHub account for CI/CD integration

Clone the repository:

```bash
git clone https://github.com/Vipin216/GitGuard.git
cd GitGuard
```

Create a virtual environment:

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install GitGuard in editable mode:

```bash
pip install -e .
```

Verify the installation:

```bash
gitguard --help
```

---

# Usage

## Scan a Repository

```bash
gitguard scan .
```

Example:

```text
GitGuard Security Scan
────────────────────────────────

[CRITICAL] config.py:18
  Type: AWS Access Key
  Confidence: HIGH

[HIGH] auth.py:32
  Type: JWT
  Confidence: HIGH

Findings: 2
```

GitGuard returns:

```text
0 → No findings
1 → Security findings detected
2 → Execution / configuration error
```

These exit codes make GitGuard suitable for CI/CD pipelines.

---

# JSON Output

Generate machine-readable output:

```bash
gitguard scan . --format json
```

Example:

```json
{
  "status": "failed",
  "files_scanned": 42,
  "findings": [
    {
      "file": "config.py",
      "line": 18,
      "secret_type": "AWS Access Key",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "match": "[REDACTED]"
    }
  ]
}
```

Detected secret values are redacted.

---

# Git History Scanning

GitGuard can inspect previous commits for secrets that may have been removed from the latest version of the repository.

```bash
gitguard history .
```

Example:

```text
GitGuard Git History Scan
────────────────────────────────

🚨 HISTORICAL FINDINGS

[CRITICAL] config.py:18
  Type: AWS Access Key
  Confidence: HIGH

Historical findings: 1
```

This helps identify secrets that may still exist in repository history even after being deleted from the current working tree.

---

# Pre-Commit Protection

Install GitGuard into an existing Git repository:

```bash
gitguard install
```

This creates a Git pre-commit hook.

The hook scans **staged files**, rather than blindly scanning the entire working directory.

```text
Developer
    ↓
git add config.py
    ↓
Staging Area
    ↓
git commit
    ↓
GitGuard
    ↓
Scan staged content
    ↓
┌───────────────┐
│ Secret found? │
└───────┬───────┘
        │
   ┌────┴────┐
   ↓         ↓
  YES        NO
   ↓         ↓
 BLOCK      ALLOW
```

Example:

```text
GitGuard Staged File Scan
────────────────────────────────

[CRITICAL] config.py:18
  Type: AWS Access Key
  Confidence: HIGH

Findings: 1
```

The commit is rejected when findings are detected.

---

# GitHub Actions

GitGuard includes a GitHub Actions workflow under:

```text
.github/workflows/gitguard.yml
```

The workflow runs on:

```yaml
on:
  push:
  pull_request:
```

The CI pipeline:

```text
GitHub Event
     ↓
Checkout Repository
     ↓
Setup Python
     ↓
Install GitGuard
     ↓
Run Security Scan
     ↓
Generate SARIF
     ↓
Upload SARIF
     ↓
Security Gate
```

A detected secret causes the GitHub Actions job to fail.

This provides a second layer of protection even if the local pre-commit hook is bypassed.

---

# SARIF & GitHub Code Scanning

GitGuard supports SARIF 2.1.0 output:

```bash
gitguard scan . --sarif results.sarif
```

The resulting report can be uploaded to GitHub Code Scanning using the GitHub Actions SARIF upload action.

```text
GitGuard
    ↓
results.sarif
    ↓
GitHub Actions
    ↓
Code Scanning
    ↓
Security Finding
```

A finding contains its source location and metadata:

```text
Rule:       AWS Access Key
Severity:   error
Confidence: HIGH
File:       config.py
Line:       18
```

The actual secret value is not included.

---

# Security Model

GitGuard follows a few important security principles.

### Never expose detected secrets

Detected values are redacted:

```text
[REDACTED]
```

rather than printed directly.

### Scan staged content

The pre-commit integration scans what is actually going to enter the commit rather than the entire working tree.

### Detect historical exposure

The history scanner checks previous commits so that removing a secret from the latest version does not hide previous exposure.

### Fail securely in automation

GitGuard uses exit codes so CI systems can treat detected secrets as security failures.

---

# Testing

GitGuard uses `pytest` for automated testing.

Run:

```bash
pytest -v
```

The test suite covers:

- AWS access key detection
- Private key detection
- JWT detection
- Password detection
- Placeholder filtering
- Entropy calculation
- High-entropy secret detection
- Clean source code
- Finding aggregation
- Git staging behavior
- Git history scanning

Test secrets are constructed dynamically where necessary so that the GitGuard repository does not accidentally trigger its own secret scanner.

---

# Project Structure

```text
GitGuard/
│
├── .github/
│   └── workflows/
│       └── gitguard.yml
│
├── gitguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── detectors.py
│   ├── entropy.py
│   ├── git_utils.py
│   ├── history.py
│   ├── hooks.py
│   ├── reporter.py
│   └── scanner.py
│
├── tests/
│   ├── test_detectors.py
│   ├── test_git_utils.py
│   └── test_history.py
│
├── .gitignore
├── pyproject.toml
├── pytest.ini
├── README.md
└── requirements.txt
```

---

# Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Regular Expressions | Pattern-based detection |
| Shannon Entropy | Unknown/high-randomness secret detection |
| Git | Repository and history integration |
| Git Hooks | Local pre-commit enforcement |
| GitHub Actions | CI/CD security enforcement |
| SARIF 2.1.0 | Standardized security reporting |
| GitHub Code Scanning | Security finding visualization |
| Pytest | Automated testing |

---

# Design Principles

GitGuard was designed around several principles:

### Reusable detection engine

Detection logic is independent of the CLI, Git hooks, and reporting formats.

### Defense in depth

Secrets are checked at multiple stages:

```text
Developer
   ↓
Pre-Commit
   ↓
GitHub CI
   ↓
Code Scanning
```

### Low-friction developer workflow

The developer can continue using normal Git commands:

```bash
git add .
git commit
git push
```

GitGuard operates automatically once the pre-commit hook and CI workflow are configured.

### Machine-readable results

JSON and SARIF outputs allow GitGuard to integrate with automation and security platforms.

---

# Limitations

GitGuard is intended as a lightweight secret detection and prevention tool rather than a replacement for dedicated enterprise secret-management platforms.

Potential limitations include:

- Pattern-based detection can produce false positives.
- Entropy-based detection cannot determine whether a random string is actually a credential.
- Git history scanning can become expensive for very large repositories.
- Detecting every possible credential format is not possible with a finite rule set.
- Finding a secret does not automatically revoke or rotate the credential.

For production environments, detected credentials should be revoked and rotated through the appropriate provider.

---

# Future Improvements

Potential future improvements include:

- Expanded secret detectors
- Configurable detection rules
- Baseline / allowlist support
- Improved false-positive reduction
- Parallel repository scanning
- Additional CI integrations
- Secret remediation guidance
- Performance optimizations for large repositories

---

# Why GitGuard?

Accidentally committing credentials is a common software security problem.

GitGuard demonstrates a defense-in-depth approach:

```text
             ┌─────────────────────┐
             │   Developer writes   │
             │       code           │
             └──────────┬──────────┘
                        ↓
                 Pre-Commit Scan
                        ↓
                  🚨 Secret?
                   /       \
                 YES        NO
                 ↓           ↓
              BLOCK        COMMIT
                              ↓
                           GitHub
                              ↓
                       GitHub Actions
                              ↓
                         GitGuard CI
                              ↓
                        SARIF Report
                              ↓
                    GitHub Code Scanning
```

The goal is to detect accidental credential exposure **as early as possible**, while providing a second security boundary in CI/CD.

---

# License

This project is available under the MIT License.