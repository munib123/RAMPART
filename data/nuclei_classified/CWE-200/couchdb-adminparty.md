# Vulnerability: CouchDB Admin Default - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchdb-adminparty.yaml`)

## Description
CouchDB is susceptible to requests in the context of an admin user.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_users/_all_docs
```

