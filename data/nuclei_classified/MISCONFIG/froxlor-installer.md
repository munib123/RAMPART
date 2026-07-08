# Vulnerability: Froxlor Server Management - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`froxlor-installer.yaml`)

## Description
Detects the Froxlor Server Management Panel installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/install.php
```

