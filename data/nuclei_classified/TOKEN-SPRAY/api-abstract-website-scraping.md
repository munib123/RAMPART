# Vulnerability: Abstract Api Web Scraping Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-website-scraping.yaml`)

## Description
Scrape and extract data from any website, with powerful options like proxy / browser customization, CAPTCHA handling, ad blocking, and more.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://scrape.abstractapi.com/v1/?api_key={{token}}&url=https://test.test
```

