# Vulnerability: Kronos Workforce Central Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kronos-workforce-central.yaml`)

## Description
Kronos Workforce Central login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wfc/portal
GET {{BaseURL}}/wfc/logon
```

