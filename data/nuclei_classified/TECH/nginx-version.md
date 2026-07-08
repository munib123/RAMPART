# Vulnerability: Nginx version detect
**Classification:** TECH
**Source:** Nuclei Template (`nginx-version.yaml`)

## Description
Some nginx servers have the version on the response header. Useful when you need to find specific CVEs on your targets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

