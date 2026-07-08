# Vulnerability: Wiki.js Setup - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`wiki-js-installer.yaml`)

## Description
Checks for the presence of a Wiki.js Setup Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

