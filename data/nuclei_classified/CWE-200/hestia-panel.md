# Vulnerability: Hestia Control Panel Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hestia-panel.yaml`)

## Description
Hestia Control Panel login was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/
```

