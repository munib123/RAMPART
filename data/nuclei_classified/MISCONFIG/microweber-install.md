# Vulnerability: Microweber Exposed Installation - Detected
**Classification:** MISCONFIG
**Source:** Nuclei Template (`microweber-install.yaml`)

## Description
Microweber Installation page was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

