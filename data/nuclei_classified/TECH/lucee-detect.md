# Vulnerability: Detect Lucee
**Classification:** TECH
**Source:** Nuclei Template (`lucee-detect.yaml`)

## Description
Lucee Server is a dynamic, Java based (JSR-223), tag and scripting language used for rapid web application development -- https://github.com/lucee/Lucee/

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lucee/doc/functions.cfm
GET {{BaseURL}}
```

