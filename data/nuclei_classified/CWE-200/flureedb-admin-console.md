# Vulnerability: FlureeDB Admin Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flureedb-admin-console.yaml`)

## Description
FlureeDB Admin Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

