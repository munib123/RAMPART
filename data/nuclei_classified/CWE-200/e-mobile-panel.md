# Vulnerability: E-mobile Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`e-mobile-panel.yaml`)

## Description
E-mobile panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.do?
GET {{BaseURL}}/login/login.do?
GET {{BaseURL}}/manager/login.do?
```

