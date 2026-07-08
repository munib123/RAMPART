# Vulnerability: ZenRows API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-zenrows.yaml`)

## Description
Web Scraping API that bypasses anti-bot solutions while offering JS rendering, and rotating proxies

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.zenrows.com/v1/?apikey={{token}}&url=https://oast.me/
```

