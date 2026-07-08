# Vulnerability: Fortinet FortiOS Management Interface Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortios-management-panel.yaml`)

## Description
Fortinet FortiOS Management interface panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?redir=/ng
```

