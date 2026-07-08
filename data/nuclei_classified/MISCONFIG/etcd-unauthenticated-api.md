# Vulnerability: etcd Unauthenticated HTTP API Leak
**Classification:** MISCONFIG
**Source:** Nuclei Template (`etcd-unauthenticated-api.yaml`)

## Description
etcd HTTP API is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v2/auth/roles
```

