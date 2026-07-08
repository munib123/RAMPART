# Vulnerability: Redash Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`redash-panel.yaml`)

## Description
Redash login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

