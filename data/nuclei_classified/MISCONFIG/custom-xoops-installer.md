# Vulnerability: XOOPS Custom - Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`custom-xoops-installer.yaml`)

## Description
Detects the presence of XOOPS Custom installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

