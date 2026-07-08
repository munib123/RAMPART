# Vulnerability: Ubersmith Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ubersmith-installer.yaml`)

## Description
Detects exposed Ubersmith Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/index.php
```

