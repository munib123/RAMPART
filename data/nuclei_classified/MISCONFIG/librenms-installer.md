# Vulnerability: LibreNMS Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`librenms-installer.yaml`)

## Description
Detects exposed LibreNMS installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/checks
```

