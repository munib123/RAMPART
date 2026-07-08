# Vulnerability: osCommerce Detection
**Classification:** OSCOMMERCE
**Source:** Nuclei Template (`oscommerce-detect.yaml`)

## Description
An instance running osCommerce is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/admin
GET {{BaseURL}}/includes/modules/
GET {{BaseURL}}/catalog/includes/javascript/oscommerce.js
GET {{BaseURL}}/checkout_payment.php
```

