# Vulnerability: Composer-auth Json File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`composer-auth-json.yaml`)

## Description
Composer Auth Josn file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.composer-auth.json
GET {{BaseURL}}/vendor/webmozart/assert/.composer-auth.json
```

