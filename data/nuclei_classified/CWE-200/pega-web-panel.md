# Vulnerability: Pega Infinity Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pega-web-panel.yaml`)

## Description
Pega Infinity login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/prweb/PRAuth/app/default/
```

