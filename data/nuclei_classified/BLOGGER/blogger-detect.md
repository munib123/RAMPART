# Vulnerability: Blogger Detection
**Classification:** BLOGGER
**Source:** Nuclei Template (`blogger-detect.yaml`)

## Description
An instance running Blogger is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/blogger.js
GET {{BaseURL}}/feeds/posts/default
GET {{BaseURL}}/search
```

