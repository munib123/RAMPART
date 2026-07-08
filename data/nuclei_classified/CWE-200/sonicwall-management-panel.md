# Vulnerability: SonicWall Management Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonicwall-management-panel.yaml`)

## Description
SonicWall Management admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth.html
```

