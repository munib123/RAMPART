# Vulnerability: EMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ems-login-panel.yaml`)

## Description
EMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/EMSWebClient/Login.aspx
```

