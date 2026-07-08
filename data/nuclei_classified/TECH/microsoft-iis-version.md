# Vulnerability: Microsoft IIS version detect
**Classification:** TECH
**Source:** Nuclei Template (`microsoft-iis-version.yaml`)

## Description
Some Microsoft IIS servers have the version on the response header. Useful when you need to find specific CVEs on your targets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

