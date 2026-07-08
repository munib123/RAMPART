# Vulnerability: Veeam Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`veeam-panel.yaml`)

## Description
Veeam login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.aspx
```

