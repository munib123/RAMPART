# Vulnerability: Discuz! X2.5 - Path Disclosure
**Classification:** DISCUZ
**Source:** Nuclei Template (`discuz-api-pathinfo.yaml`)

## Description
Discuz! X2.5 api.php path disclosure vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api.php?mod[]=auto
```

