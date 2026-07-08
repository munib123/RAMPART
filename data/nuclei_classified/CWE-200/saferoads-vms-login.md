# Vulnerability: Saferoads VMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`saferoads-vms-login.yaml`)

## Description
Saferoads VMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

