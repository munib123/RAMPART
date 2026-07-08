# Vulnerability: Infinispan Console - Detection
**Classification:** TECH
**Source:** Nuclei Template (`infinispan-detect.yaml`)

## Description
Infinispan is an open-source in-memory data grid by Red Hat that exposes a management console under `/console/welcome` and a REST API under `/rest/v2/` on the default port 11222. This template fingerprints Infinispan by matching the unique HTML console markers and the Digest authentication challenge from the REST API.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console/welcome
GET {{BaseURL}}/rest/v2/cache-managers/default
```

