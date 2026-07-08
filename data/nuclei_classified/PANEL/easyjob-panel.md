# Vulnerability: EasyJOB Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`easyjob-panel.yaml`)

## Description
EasyJOB login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/easy/app/Account/Login
```

