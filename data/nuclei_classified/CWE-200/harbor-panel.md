# Vulnerability: Harbor Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`harbor-panel.yaml`)

## Description
Harbor login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v2.0/systeminfo
GET {{BaseURL}}/api/systeminfo
GET {{BaseURL}}/account/sign-in
GET {{BaseURL}}/harbor/sign-in
```

