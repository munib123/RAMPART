# Vulnerability: Invicti Enterprise Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`invicti-enterprise-installer.yaml`)

## Description
Detects exposed Invicti Enterprise Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard/database/
```

