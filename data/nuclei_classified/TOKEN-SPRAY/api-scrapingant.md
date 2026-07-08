# Vulnerability: ScrapingAnt API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scrapingant.yaml`)

## Description
Headless Chrome scraping with a simple API

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.scrapingant.com/v1/general HTTP/1.1
Host: api.scrapingant.com
x-api-key: {{token}}
Content-Type: application/json

{"url": "https://example.com"}
```

