# Vulnerability: Etcd Version - Detect
**Classification:** TECH
**Source:** Nuclei Template (`etcd-version.yaml`)

## Description
Template detects Etcd version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/version
```

