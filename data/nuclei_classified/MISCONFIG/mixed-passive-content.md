# Vulnerability: Mixed Passive Content
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mixed-passive-content.yaml`)

## Description
This check detects if there are any passive content being loaded over HTTP instead of HTTPS.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

