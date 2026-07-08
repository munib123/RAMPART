# Vulnerability: Sitemap Detection
**Classification:** MISCELLANEOUS
**Source:** Nuclei Template (`sitemap-detect.yaml`)

## Description
A sitemap is a file where you provide information about the pages, videos, and other files on your site, and the relationships between them.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sitemap.xml
GET {{BaseURL}}/sitemap.xsl
GET {{BaseURL}}/sitemap.xsd
```

