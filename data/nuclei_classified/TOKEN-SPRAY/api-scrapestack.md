# Vulnerability: Scrapestack API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scrapestack.yaml`)

## Description
Real-time, Scalable Proxy & Web Scraping REST API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.scrapestack.com/scrape?access_key={{token}}&url=https://oast.me
```

