# Vulnerability: Strapi CMS detect
**Classification:** TECH
**Source:** Nuclei Template (`strapi-cms-detect.yaml`)

## Description
Open source Node.js Headless CMS to easily build customisable APIs

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/init
```

