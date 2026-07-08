# Vulnerability: CockroachDB Information Disclosure
**Classification:** COCKROACHDB
**Source:** Nuclei Template (`cockroachdb-information-disclosure.yaml`)

## Description
CockroachDB exposed the Statements Admin UI page and the HTTP endpoint /_status/statements in ways that let non-admin users (and in some builds, unauthenticated callers) see SQL text executed across the cluster.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/_status/statements
```

