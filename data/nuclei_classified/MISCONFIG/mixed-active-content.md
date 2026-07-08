# Vulnerability: Mixed Active Content
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mixed-active-content.yaml`)

## Description
This check detects if there are any active content loaded over HTTP instead of HTTPS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

