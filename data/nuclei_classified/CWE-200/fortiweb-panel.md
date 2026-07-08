# Vulnerability: Fortinet FortiWeb Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortiweb-panel.yaml`)

## Description
Fortinet FortiWeb login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

