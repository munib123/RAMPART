# Vulnerability: SiteCore Debug Page
**Classification:** DEBUG
**Source:** Nuclei Template (`sitecore-debug-page.yaml`)

## Description
SiteCore debug page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sitecore/'
```

