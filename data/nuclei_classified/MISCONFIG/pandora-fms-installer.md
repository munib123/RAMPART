# Vulnerability: Pandora FMS Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`pandora-fms-installer.yaml`)

## Description
Detects exposed Pandora FMS installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

