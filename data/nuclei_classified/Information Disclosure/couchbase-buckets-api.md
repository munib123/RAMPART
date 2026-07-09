# Nuclei Template: Couchbase Buckets Unauthenticated REST API - Detect
**Template ID:** couchbase-buckets-api
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`couchbase-buckets-api.yaml`)

## Vulnerability Information & PoC

## Description
Couchbase Buckets REST API without authentication was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pools/default/buckets
```

## References
- https://docs.couchbase.com/server/current/rest-api/rest-bucket-intro.html
- https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-couchbase-bucket.html
