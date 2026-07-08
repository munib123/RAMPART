# Vulnerability: Tiny File Manager - Unauthorized Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tiny-file-manager-unauth.yaml`)

## Description
Unauthenticated Tiny File Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php
```

