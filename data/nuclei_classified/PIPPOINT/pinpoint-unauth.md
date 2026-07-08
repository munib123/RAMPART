# Vulnerability: PinPoint Unauth
**Classification:** PIPPOINT
**Source:** Nuclei Template (`pinpoint-unauth.yaml`)

## Description
PinPoint is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/applications.pinpoint
```

