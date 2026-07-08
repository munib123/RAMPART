# Vulnerability: Shopware CMS detect
**Classification:** TECH
**Source:** Nuclei Template (`shopware-detect.yaml`)

## Description
Detects Shopware CMS

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
GET {{BaseURL}}/backend
```

