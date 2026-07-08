# Vulnerability: FortiADC Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortiadc-panel.yaml`)

## Description
FortiADC login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/#navigate/Login
```

