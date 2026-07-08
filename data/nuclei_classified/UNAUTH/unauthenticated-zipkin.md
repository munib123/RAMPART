# Vulnerability: Zipkin Discovery
**Classification:** UNAUTH
**Source:** Nuclei Template (`unauthenticated-zipkin.yaml`)

## Description
Unauthenticated access to Zipkin was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.json
```

