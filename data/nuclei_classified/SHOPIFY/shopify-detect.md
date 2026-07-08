# Vulnerability: Shopify Detection
**Classification:** SHOPIFY
**Source:** Nuclei Template (`shopify-detect.yaml`)

## Description
An instance running Shopify is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/admin
GET {{BaseURL}}/shopify_app
GET {{BaseURL}}/shopify_api
GET {{BaseURL}}/favicon.ico
```

