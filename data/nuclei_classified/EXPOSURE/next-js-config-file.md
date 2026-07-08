# Vulnerability: Next JS Config - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`next-js-config-file.yaml`)

## Description
Next JS Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/next.config.js
```

