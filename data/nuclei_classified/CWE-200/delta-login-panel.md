# Vulnerability: Delta Controls Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`delta-login-panel.yaml`)

## Description
Delta Controls admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/deltaweb/hmi_login.asp
```

