# Vulnerability: SonicWall Email Security Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sonicwall-email-security-detect.yaml`)

## Description
SonicWall Email Security panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
```

