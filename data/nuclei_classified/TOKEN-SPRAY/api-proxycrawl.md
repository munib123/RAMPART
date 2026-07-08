# Vulnerability: ProxyCrawl API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-proxycrawl.yaml`)

## Description
Scraping and crawling anticaptcha service

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.proxycrawl.com/leads?token={{token}}&domain=www.amazon.com
```

