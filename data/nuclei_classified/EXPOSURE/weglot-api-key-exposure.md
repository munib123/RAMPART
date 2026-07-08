# Vulnerability: Weglot API Key - Exposed
**Classification:** EXPOSURE
**Source:** Nuclei Template (`weglot-api-key-exposure.yaml`)

## Description
Detected Weglot API key was found exposed in a publicly accessible JavaScript file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scripts/weglot.js
```

