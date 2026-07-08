# Vulnerability: Confluence Detection
**Classification:** TECH
**Source:** Nuclei Template (`confluence-detect.yaml`)

## Description
This nuclei template is used to detect the presence of Confluence, a popular collaboration software.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dologin.action
GET {{BaseURL}}
GET {{BaseURL}}/pages
GET {{BaseURL}}/confluence
GET {{BaseURL}}/wiki
```

