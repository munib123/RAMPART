# Vulnerability: SonicWall Analyzer Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonicwall-analyzer-login.yaml`)

## Description
SonicWall Analyzer login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sgms/auth
```

