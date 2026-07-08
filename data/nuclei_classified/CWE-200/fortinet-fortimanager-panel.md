# Vulnerability: Fortinet FortiManager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortinet-fortimanager-panel.yaml`)

## Description
Fortinet FortiManager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/p/login/
```

