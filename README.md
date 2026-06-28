# SSLEX

> SSL/TLS Scanner — full certificate and protocol security analysis with Metasploit-style interactive shell.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

SSLEX performs full SSL/TLS security audits — checking supported protocol versions, cipher suite strength, certificate validity, security headers, and known vulnerabilities. Zero external dependencies, uses only Python's built-in `ssl` module.

---

## Modules

| Module | Description |
|---|---|
| `ssl/scan` | Full TLS audit — protocols, ciphers, HSTS, vulnerability checks |
| `ssl/cert` | Certificate deep-dive — SANs, expiry, CT logs via crt.sh, chain validation |

---

## Features

- **Protocol detection** — TLS 1.0, 1.1, 1.2, 1.3 support check with severity rating
- **Cipher audit** — detects RC4, DES, 3DES, NULL, EXPORT and other weak ciphers
- **Certificate analysis** — expiry, hostname match, self-signed, key size
- **HSTS check** — presence and max-age validation
- **CT log lookup** — queries crt.sh for Certificate Transparency entries
- **Vulnerability indicators** — BEAST, POODLE, CRIME context from protocol results
- **Zero dependencies** — uses only Python standard library

---

## Requirements

```bash
# No external dependencies required
python3 --version  # 3.10+
```

---

## Installation

```bash
git clone https://github.com/NeiveZ/SSLEX.git
cd SSLEX
chmod +x sslex.sh
./sslex.sh
```

---

## Usage

```
sslex > use ssl/scan
sslex > use ssl/cert
```

### Core commands

```
use <module>            Load a module
set TARGET <host>       Set target hostname
set PORT <port>         Set port (default: 443)
run                     Execute module
show findings           View results
report [txt|json|html]  Export report
```

---

## Examples

**Full TLS scan:**
```
sslex > use ssl/scan
sslex (ssl/scan) > set TARGET example.com
sslex (ssl/scan) > run
```

**Non-standard port:**
```
sslex (ssl/scan) > set TARGET api.example.com
sslex (ssl/scan) > set PORT 8443
sslex (ssl/scan) > run
```

**Certificate deep inspection:**
```
sslex > use ssl/cert
sslex (ssl/cert) > set TARGET example.com
sslex (ssl/cert) > set CRT_SH true
sslex (ssl/cert) > run
```

**Export HTML report:**
```
sslex > report html tls_audit
```

---

## Output

```
sslex (ssl/scan) > run

── SSL/TLS Scan — example.com:443 ──────────────────────

[*] Checking certificate...
    Common Name   : example.com
    Issuer        : Let's Encrypt
    Expires       : 2024-09-15 (87 days)
[OK]  Hostname matches certificate

[*] Checking protocol support...
[OK]     TLSv1.0 — not supported (good)
[OK]     TLSv1.1 — not supported (good)
[OK]     TLSv1.2 — supported
[OK]     TLSv1.3 — supported

[*] Checking cipher suites...
[STRONG]  Negotiated: TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bits)

[*] Running vulnerability checks...
[OK]      HSTS: max-age=31536000; includeSubDomains
[INFO]    Heartbleed: Manual verification recommended

[+] Scan complete — 0 HIGH/CRITICAL  0 MEDIUM  0 LOW  8 OK
```

---

## Severity Guide

| Severity | Condition |
|---|---|
| CRITICAL | SSLv2, SSLv3, alg:none, expired cert |
| HIGH | TLS 1.0/1.1, hostname mismatch, RC4/DES ciphers |
| MEDIUM | Missing HSTS, TLS 1.2 not supported, self-signed cert |
| LOW | Short HSTS max-age, long cert expiry |
| OK | Correctly configured |

---

## Repository Structure

```
SSLEX/
├── sslex.py              # Interactive shell
├── sslex.sh              # Launcher
├── modules/
│   ├── tls_scan.py       # Protocol, cipher, vulnerability scan
│   ├── cert_check.py     # Certificate details and CT logs
│   └── report_gen.py     # Report generator
└── utils/
    ├── colors.py
    └── session.py
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
