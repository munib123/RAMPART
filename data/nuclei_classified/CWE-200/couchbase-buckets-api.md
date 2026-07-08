# Vulnerability: Couchbase Buckets Unauthenticated REST API - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`couchbase-buckets-api.yaml`)

## Description
Couchbase Buckets REST API without authentication was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pools/default/buckets
```

