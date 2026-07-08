# Vulnerability: Wallix Access Manager Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wallix-accessmanager-panel.yaml`)

## Description
Wallix Access Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wabam
GET {{BaseURL}}/wabam/favicon.ico
```

