# Vulnerability: Apache CouchDB - Unauthenticated Access
**Classification:** APACHE
**Source:** Nuclei Template (`apache-couchdb-unauth.yaml`)

## Description
Apache CouchDB is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_config
```

