# Vulnerability: XDS-AMR Status Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xds-amr-status.yaml`)

## Description
XDS-AMR Status login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

