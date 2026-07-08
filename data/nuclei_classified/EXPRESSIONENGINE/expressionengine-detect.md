# Vulnerability: ExpressionEngine Detection
**Classification:** EXPRESSIONENGINE
**Source:** Nuclei Template (`expressionengine-detect.yaml`)

## Description
An instance running ExpressionEngine is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/system/
GET {{BaseURL}}/themes/
GET {{BaseURL}}/index.php
GET {{BaseURL}}/admin.php
GET {{BaseURL}}/cp/
```

