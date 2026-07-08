# Vulnerability: WordPress Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wordpress-login.yaml`)

## Description
WordPress login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-login.php
```

