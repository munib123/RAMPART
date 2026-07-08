# Vulnerability: OpenCart Detection
**Classification:** OPENCART
**Source:** Nuclei Template (`opencart-detect.yaml`)

## Description
An instance running OpenCart is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/admin
GET {{BaseURL}}/catalog/view/javascript/opencart.js
GET {{BaseURL}}/index.php?route=common/home
GET {{BaseURL}}/oc-admin
```

