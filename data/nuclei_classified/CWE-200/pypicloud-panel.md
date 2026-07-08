# Vulnerability: PyPICloud Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pypicloud-panel.yaml`)

## Description
PyPLCloud login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

