# Vulnerability: RethinkDB Administration Console - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rethinkdb-admin-console.yaml`)

## Description
RethinkDB Administration Console was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#dashboard
```

