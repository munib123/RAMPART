# Vulnerability: Apache CouchDB Fauxton Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchdb-fauxton.yaml`)

## Description
Apache CouchDB Fauxton panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

