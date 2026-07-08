# Vulnerability: Concrete5 Detection
**Classification:** CONCRETE5
**Source:** Nuclei Template (`concrete5-detect.yaml`)

## Description
An instance running Concrete5 is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/index.php
GET {{BaseURL}}/concrete/js/build/
GET {{BaseURL}}/concrete/block/
GET {{BaseURL}}/dashboard/
```

