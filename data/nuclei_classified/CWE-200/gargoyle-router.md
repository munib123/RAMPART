# Vulnerability: Gargoyle Router Management Utility Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gargoyle-router.yaml`)

## Description
Gargoyle Router Management Utility admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.sh
```

