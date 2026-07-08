# Vulnerability: AirNotifier Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`airnotifier-panel.yaml`)

## Description
AirNotifier login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

