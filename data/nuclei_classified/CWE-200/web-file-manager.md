# Vulnerability: Web File Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`web-file-manager.yaml`)

## Description
Web File Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login
```

