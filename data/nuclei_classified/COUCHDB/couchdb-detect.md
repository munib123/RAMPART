# Vulnerability: CouchDB - Detect
**Classification:** COUCHDB
**Source:** Nuclei Template (`couchdb-detect.yaml`)

## Description
Detects instances of Apache CouchDB server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

