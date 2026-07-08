# Vulnerability: Larvel Debug Method Enabled
**Classification:** DEBUG
**Source:** Nuclei Template (`laravel-debug-error.yaml`)

## Description
Larvel Debug method is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}///////this-should-not-exist,.<>!@#$%^&*()_+
GET {{BaseURL}}/%00
```

