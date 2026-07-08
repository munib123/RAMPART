# Vulnerability: Looker Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`looker-panel.yaml`)

## Description
Looker login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

