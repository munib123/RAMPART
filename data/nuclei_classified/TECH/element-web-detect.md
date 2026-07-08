# Vulnerability: Element Web - Detect
**Classification:** TECH
**Source:** Nuclei Template (`element-web-detect.yaml`)

## Description
Identify if a web application is vanilla Element Web and return the version

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/manifest.json
GET {{BaseURL}}/version
```

