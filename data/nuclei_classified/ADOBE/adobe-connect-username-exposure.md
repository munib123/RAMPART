# Vulnerability: Adobe Connect Username Exposure
**Classification:** ADOBE
**Source:** Nuclei Template (`adobe-connect-username-exposure.yaml`)

## Description
Adobe Connect Username is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/help/support
```

