# Vulnerability: Wix Detection
**Classification:** WIX
**Source:** Nuclei Template (`Wix-detect.yaml`)

## Description
An instance running Wix is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/_static/
GET {{BaseURL}}/wix-api
GET {{BaseURL}}/user/login
GET {{BaseURL}}/wix.js
```

