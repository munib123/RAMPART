# Vulnerability: Unauthenticated Gloo UI
**Classification:** UNAUTH
**Source:** Nuclei Template (`gloo-unauth.yaml`)

## Description
Gloo UI is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fed.rpc.solo.io.GlooInstanceApi/ListClusterDetails
```

