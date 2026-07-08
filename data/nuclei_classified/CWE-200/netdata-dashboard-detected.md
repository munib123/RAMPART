# Vulnerability: Netdata Dashboard Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netdata-dashboard-detected.yaml`)

## Description
Netdata Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

