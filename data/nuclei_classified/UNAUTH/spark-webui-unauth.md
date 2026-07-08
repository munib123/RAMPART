# Vulnerability: Unauthenticated Spark WebUI
**Classification:** UNAUTH
**Source:** Nuclei Template (`spark-webui-unauth.yaml`)

## Description
Spark WebUI is exposed to external users without any authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

