# Vulnerability: Django Detection
**Classification:** DJANGO
**Source:** Nuclei Template (`django-detect.yaml`)

## Description
An instance running Django is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/admin/
GET {{BaseURL}}/static/
GET {{BaseURL}}/media/
GET {{BaseURL}}/index.php
GET {{BaseURL}}/django-admin/
```

