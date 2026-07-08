# Vulnerability: Akamai Cache Detection
**Classification:** CACHE
**Source:** Nuclei Template (`akamai-cache-detect.yaml`)

## Description
Sends a HEAD request with a Pragma header value of "akamai-x-cache-on" and looks for an akamai-specific response header value.

## Vulnerable Code Pattern / Exploit Payload
```http
HEAD {{BaseURL}}
```

