# Vulnerability: Nuxtjs Config File - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`nuxtjs-config-file.yaml`)

## Description
Nuxtjs Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nuxt.config.js
```

