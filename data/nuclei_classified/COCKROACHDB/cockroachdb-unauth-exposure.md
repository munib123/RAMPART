# Vulnerability: CockroachDB Unauthenticated Console Exposure
**Classification:** COCKROACHDB
**Source:** Nuclei Template (`cockroachdb-unauth-exposure.yaml`)

## Description
Unauthenticated access to the CockroachDB console allows viewing the cluster nodes and server version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/_status/nodes
```

