# Vulnerability: AChecker Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`achecker-panel.yaml`)

## Description
AChecker login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/checker/login.php
```

