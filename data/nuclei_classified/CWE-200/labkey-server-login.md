# Vulnerability: LabKey Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`labkey-server-login.yaml`)

## Description
LabKey Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/labkey/home/login-login.view
GET {{BaseURL}}/login/home/login.view
```

