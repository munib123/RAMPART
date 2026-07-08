# Vulnerability: Couchbase Server Console - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchbase-server-console.yaml`)

## Description
Couchbase Server administrative console was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/index.html
```

