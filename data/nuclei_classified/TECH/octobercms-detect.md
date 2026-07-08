# Vulnerability: OctoberCMS detect
**Classification:** TECH
**Source:** Nuclei Template (`octobercms-detect.yaml`)

## Description
Detects OctoberCMS

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/modules/system/assets/js/framework.combined-min.js
```

