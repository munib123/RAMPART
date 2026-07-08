# Vulnerability: Apache CouchDB Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchdb-exposure.yaml`)

## Description
Apache CouchDB panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_all_dbs
```

