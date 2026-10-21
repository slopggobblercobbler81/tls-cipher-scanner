# 🔒 tls-cipher-scanner

[![CI](https://github.com/slopggobblercobbler81/tls-cipher-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/tls-cipher-scanner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> **High-assurance CLI and Python library to audit SSL/TLS protocol versions, cipher suites, certificate validity, and cryptographic postures of remote endpoints.**

---

## ⚡ Overview

`tls-cipher-scanner` is a zero-dependency, lightweight command-line security auditor designed for developers, penetration testers, and DevOps engineers. It connects to target hosts, audits supported TLS protocol versions (detecting obsolete SSLv3, TLS 1.0, and TLS 1.1), flags deprecated or insecure cipher suites (RC4, 3DES, MD5, export-grade ciphers, CBC mode), inspects X.509 certificate expiry and subject alternative names, and generates clean human-readable or machine-parsable JSON audit reports.

---

## 🚀 Key Features

- **Protocol Version Auditing:**
  - Flags obsolete and broken protocols (`SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`).
  - Validates active support for modern, secure protocols (`TLSv1.2`, `TLSv1.3`).
- **Cipher Suite Inspection:**
  - Flags insecure ciphers containing `RC4`, `DES`, `3DES`, `MD5`, `NULL`, `EXPORT`, and `anon`.
  - Verifies presence of modern AEAD cipher suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- **Certificate Health Checks:**
  - Evaluates remaining certificate validity duration and expiration dates.
  - Validates Common Names (CN) and Subject Alternative Names (SANs) against target hostnames.
- **CI/CD Integration:**
  - Strict exit code protocols for automated security gating in pipelines.
  - Formatted JSON output option (`--json`) for automated vulnerability ingestion and reporting.
- **Zero Third-Party Dependencies:**
  - Built purely on Python's built-in `ssl` and `socket` standard libraries for maximum portability and fast cold starts.

---

## 📦 Installation

```bash
# Clone and install locally
git clone https://github.com/slopggobblercobbler81/tls-cipher-scanner.git
cd tls-cipher-scanner
pip install .
```

Or using [uv](https://github.com/astral-sh/uv):
```bash
uv pip install .
```

---

## 💻 Usage & CLI Examples

### Standard Domain Audit
```bash
tls-cipher-scanner example.com
```

### Specific Port or URL Scheme
```bash
tls-cipher-scanner https://api.internal.corp:8443
```

### Structured JSON Output for CI/CD Gates
```bash
tls-cipher-scanner example.com:443 --json > tls_audit_report.json
```

### Custom Timeout and Strict Minimum Protocol
```bash
tls-cipher-scanner secure.banking.com --timeout 5 --min-tls 1.2
```

---

## 🧭 Companion Tools & Ecosystem Cross-References

`tls-cipher-scanner` focuses on fast, zero-dependency endpoint verification and complements leading open-source cryptography and TLS evaluation tools:

### Upstream TLS & Cryptography Companion Tools
- [`drwetter/testssl.sh`](https://github.com/drwetter/testssl.sh) — Comprehensive command-line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols, as well as recent cryptographic flaws (Heartbleed, POODLE, ROBOT).
- [`nabla-c0d3/sslyze`](https://github.com/nabla-c0d3/sslyze) — Fast and powerful SSL/TLS scanning library and CLI for deep cryptographic configuration analysis.
- [`openssl/openssl`](https://github.com/openssl/openssl) — The canonical TLS/SSL toolkit and cryptographic library underlying internet security.
- [`rustls/rustls`](https://github.com/rustls/rustls) — Modern, memory-safe TLS library written in Rust, offering strong resistance to memory-corruption vulnerabilities.
- [`jtesta/ssh-audit`](https://github.com/jtesta/ssh-audit) — Companion SSH server and client configuration auditor for banner, key exchange, encryption, and MAC algorithms.
- [`FiloSottile/mkcert`](https://github.com/FiloSottile/mkcert) — Simple zero-config tool for making locally-trusted development certificates.

### Sibling Security & CI Guard Utilities
- [`jwt-audit-sentinel`](https://github.com/slopggobblercobbler81/jwt-audit-sentinel) — Developer CLI and security auditor for JSON Web Tokens (JWT) detecting weak algorithms, expiry pitfalls, and misconfigurations.
- [`secret-leak-guard`](https://github.com/slopggobblercobbler81/secret-leak-guard) — High-performance regex and Shannon entropy scanner for tokens/secrets in git diffs and codebases.
- [`dockerfile-sec-guard`](https://github.com/slopggobblercobbler81/dockerfile-sec-guard) — Fast CLI security scanner and hardening linter for Dockerfiles with SARIF output.
- [`repo-hygiene-cli`](https://github.com/slopggobblercobbler81/repo-hygiene-cli) — Developer CLI to audit git repositories for security hygiene, sensitive files in git history, and missing `.gitignore` rules.

---

## 🧪 Testing

Run unit and integration tests with `pytest`:

```bash
pip install -e .[dev]
pytest -v
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
