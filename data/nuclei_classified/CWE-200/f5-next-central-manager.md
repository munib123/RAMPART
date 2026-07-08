# Vulnerability: F5 Next Central Manager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`f5-next-central-manager.yaml`)

## Description
F5 Next Central Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gui/login
```

