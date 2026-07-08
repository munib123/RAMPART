# Vulnerability: Flask Detection
**Classification:** FLASK
**Source:** Nuclei Template (`flask-detect.yaml`)

## Description
An instance running Flask is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/index.php
GET {{BaseURL}}/static/
GET {{BaseURL}}/flask/
GET {{BaseURL}}/health/
```

