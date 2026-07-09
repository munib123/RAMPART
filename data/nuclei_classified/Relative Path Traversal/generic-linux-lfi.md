# Nuclei Template: Generic Linux - Local File Inclusion
**Template ID:** generic-linux-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`generic-linux-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Generic Linux is subject to Local File Inclusion - the vulnerability was identified by requesting /etc/passwd from the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://github.com/imhunterand/ApachSAL/blob/main/assets/exploits.json
