# Vulnerability: Axigen Web Admin Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`axigen-webadmin.yaml`)

## Description
An Axigen Web Admin panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

