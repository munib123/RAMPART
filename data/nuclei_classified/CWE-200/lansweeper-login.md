# Vulnerability: Lansweeper Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lansweeper-login.yaml`)

## Description
Lansweeper login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.aspx
```

