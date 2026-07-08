# Vulnerability: Squarespace Detection
**Classification:** SQUARESPACE
**Source:** Nuclei Template (`squarespace-detect.yaml`)

## Description
An instance running Squarespace is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/_static/
GET {{BaseURL}}/squarespace.js
GET {{BaseURL}}/config.json
GET {{BaseURL}}/media-cache
```

