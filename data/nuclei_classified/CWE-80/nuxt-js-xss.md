# Vulnerability: Nuxt.js Error Page - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`nuxt-js-xss.yaml`)

## Description
The developer server unsafely renders the stack trace within errors. This can be manipulated by sending a specially crafted request.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/__nuxt_error?stack=%0A{{url_encode(payload)}}
```

