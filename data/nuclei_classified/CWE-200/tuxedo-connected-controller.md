# Vulnerability: Tuxedo Connected Controller Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tuxedo-connected-controller.yaml`)

## Description
Tuxedo Connected Controller login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

