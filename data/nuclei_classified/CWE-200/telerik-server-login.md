# Vulnerability: Telerik Report Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`telerik-server-login.yaml`)

## Description
Telerik Report Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Account/Login
```

