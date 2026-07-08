# Vulnerability: XWiki - Detection
**Classification:** XWIKI
**Source:** Nuclei Template (`xwiki-detect.yaml`)

## Description
XWiki Platform was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/xwiki/
```

