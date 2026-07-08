# Vulnerability: Ruijie Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ruijie-information-disclosure.yaml`)

## Description
Ruijie login panel was detected and leaks authentication credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

