# Vulnerability: Checkmate Login Panel - Detect
**Classification:** CWE-668
**Source:** Nuclei Template (`checkmate-panel.yaml`)

## Description
Checkmate administrative login page was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

