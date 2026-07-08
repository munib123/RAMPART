# Vulnerability: ScraperAPI API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scraperapi.yaml`)

## Description
Easily build scalable web scrapers

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://api.scraperapi.com/account?api_key={{token}}
```

