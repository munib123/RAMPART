# Vulnerability: Bitrix Detection
**Classification:** BITRIX
**Source:** Nuclei Template (`bitrix-detect.yaml`)

## Description
An instance running Bitrix is detected by looking for specific HTTP headers, HTML tags, and known endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/robots.txt
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/bitrix/js/main/core/core_min.js
GET {{BaseURL}}/bitrix/admin/
GET {{BaseURL}}/bitrix/templates/
GET {{BaseURL}}/bitrix/panel/
```

