# Vulnerability: Cloudflare User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cloudflare.yaml`)

## Description
Cloudflare user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.cloudflare.com/u/{{user}}
```

