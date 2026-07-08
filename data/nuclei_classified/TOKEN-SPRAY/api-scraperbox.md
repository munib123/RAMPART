# Vulnerability: ScraperBox API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-scraperbox.yaml`)

## Description
Undetectable web scraping API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.scraperbox.com/scrape?token={{token}}&url=https://oast.me
```

