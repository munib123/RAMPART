# Vulnerability: Polycom Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`polycom-admin-detect.yaml`)

## Description
Polycom admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/systemstatus.xml
```

