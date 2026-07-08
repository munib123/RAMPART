# Vulnerability: ScrapingDog API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scrapingdog.yaml`)

## Description
Proxy API for Web scraping

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.scrapingdog.com/scrape?api_key={{token}}&url=https://example.com/ip&dynamic=false
```

