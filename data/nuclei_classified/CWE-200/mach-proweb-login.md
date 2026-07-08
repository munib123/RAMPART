# Vulnerability: MACH-ProWeb Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mach-proweb-login.yaml`)

## Description
MACH-ProWeb login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

