# Vulnerability: Internet Multi Server Control Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`i-mscp-panel.yaml`)

## Description
Internet Multi Server Control Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php
```

