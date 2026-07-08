# Vulnerability: XOOPS Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`xoops-installer.yaml`)

## Description
Detects exposed XOOPS Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/page_start.php
```

