# Vulnerability: Weebly Detection
**Classification:** WEEBLY
**Source:** Nuclei Template (`weebly-detect.yaml`)

## Description
An instance running Weebly is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/index.php
GET {{BaseURL}}/weebly/
GET {{BaseURL}}/site/
```

