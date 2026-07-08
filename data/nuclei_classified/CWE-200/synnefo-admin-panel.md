# Vulnerability: Synnefo Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`synnefo-admin-panel.yaml`)

## Description
Synnefo Admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/synnefoclient/
```

