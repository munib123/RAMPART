# Vulnerability: Default Web Application Detection
**Classification:** TECH
**Source:** Nuclei Template (`default-detect-generic.yaml`)

## Description
Catch-all for detecting default installations of web applications using common phrases found in default install pages

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

