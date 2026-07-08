# Vulnerability: GLPI Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`glpi-installer.yaml`)

## Description
Detects exposed GLPI Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/install.php
```

