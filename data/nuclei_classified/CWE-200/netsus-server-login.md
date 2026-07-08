# Vulnerability: NetSUS Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netsus-server-login.yaml`)

## Description
NetSUS Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webadmin/
```

