# Vulnerability: Apache Storm Unauth
**Classification:** APACHE
**Source:** Nuclei Template (`apache-storm-unauth.yaml`)

## Description
Apache Storm instance is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/cluster/summary
```

