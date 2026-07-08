# Vulnerability: Appspace Login Panel - Detect
**Classification:** APPSPACE
**Source:** Nuclei Template (`appspace-panel.yaml`)

## Description
Appspace is the workplace experience platform for your whole team that lets you manage it all – from employee communications to your physical office spaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/app/login.aspx
GET {{BaseURL}}/signin/#!/login?returnUrl=%2Fapp%2Fdefault.aspx
```

