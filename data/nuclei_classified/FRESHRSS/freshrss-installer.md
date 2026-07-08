# Vulnerability: FreshRSS - Installation
**Classification:** FRESHRSS
**Source:** Nuclei Template (`freshrss-installer.yaml`)

## Description
FreshRSS Installation panel has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/i/?rid
```

