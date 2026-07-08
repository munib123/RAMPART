# Vulnerability: VIP-blog User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vip-blog.yaml`)

## Description
VIP-blog user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{user}}.vip-blog.com
```

