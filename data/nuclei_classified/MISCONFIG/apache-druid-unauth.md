# Vulnerability: Apache Druid Unauth
**Classification:** MISCONFIG
**Source:** Nuclei Template (`apache-druid-unauth.yaml`)

## Description
Apache Druid is exposed to external users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/unified-console.html
```

