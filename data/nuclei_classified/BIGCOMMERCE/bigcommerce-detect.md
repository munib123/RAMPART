# Vulnerability: BigCommerce Detection
**Classification:** BIGCOMMERCE
**Source:** Nuclei Template (`bigcommerce-detect.yaml`)

## Description
An instance running BigCommerce is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/bigcommerce.js
GET {{BaseURL}}/stores
GET {{BaseURL}}/cart
GET {{BaseURL}}/admin
```

