# Vulnerability: Freshrss Admin Dashboard - Exposed
**Classification:** FRESHRSS
**Source:** Nuclei Template (`freshrss-unauth.yaml`)

## Description
Freshrss Admin Dashboard has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/i/?a=logs
```

