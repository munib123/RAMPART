# Vulnerability: Sauter moduWeb Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sauter-login.yaml`)

## Description
Sauter moduWeb login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?locale=en
```

