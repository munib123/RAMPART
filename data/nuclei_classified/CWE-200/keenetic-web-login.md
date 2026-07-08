# Vulnerability: Keenetic Web Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`keenetic-web-login.yaml`)

## Description
Keenetic Web login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login#goto=%2Fdashboard
```

