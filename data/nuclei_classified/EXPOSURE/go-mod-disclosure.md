# Vulnerability: Go.mod Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`go-mod-disclosure.yaml`)

## Description
go.mod internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/go.mod
```

