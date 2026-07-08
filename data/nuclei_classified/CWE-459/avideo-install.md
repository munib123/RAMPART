# Vulnerability: AVideo Installer - Detect
**Classification:** CWE-459
**Source:** Nuclei Template (`avideo-install.yaml`)

## Description
AVideo installer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

