# Vulnerability: Netdata Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netdata-panel.yaml`)

## Description
Netdata panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/info
GET {{BaseURL}}/api/v2/info
GET {{BaseURL}}/sign-in
```

