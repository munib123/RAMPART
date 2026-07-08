# Vulnerability: GetSimple CMS Detection
**Classification:** TECH
**Source:** Nuclei Template (`getsimple-cms-detect.yaml`)

## Description
Template to detect a running GetSimple CMS instance

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/readme.txt
```

