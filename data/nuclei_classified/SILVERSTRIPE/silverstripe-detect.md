# Vulnerability: SilverStripe Detection
**Classification:** SILVERSTRIPE
**Source:** Nuclei Template (`silverstripe-detect.yaml`)

## Description
An instance running SilverStripe is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/index.php
GET {{BaseURL}}/assets/
GET {{BaseURL}}/cms/
GET {{BaseURL}}/admin/
GET {{BaseURL}}/themes/
```

