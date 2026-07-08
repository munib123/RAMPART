# Vulnerability: ProxyKingdom API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-proxykingdom.yaml`)

## Description
Rotating Proxy API that produces a working proxy on every request

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.proxykingdom.com/proxy?token={{token}}
```

