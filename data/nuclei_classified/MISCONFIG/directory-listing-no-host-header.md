# Vulnerability: Directory Listing - No Host header
**Classification:** MISCONFIG
**Source:** Nuclei Template (`directory-listing-no-host-header.yaml`)

## Description
The HTTP server is configured to list files in the root directory when no Host header is provided.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

@Host: {{Hostname}}
GET / HTTP/1.0
```

