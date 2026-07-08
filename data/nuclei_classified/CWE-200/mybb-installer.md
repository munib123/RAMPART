# Vulnerability: MyBB Installation Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mybb-installer.yaml`)

## Description
Detects exposed MyBB Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

