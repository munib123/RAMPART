# Vulnerability: Zipline - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`zipline-installer.yaml`)

## Description
Zipline installer setup was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

