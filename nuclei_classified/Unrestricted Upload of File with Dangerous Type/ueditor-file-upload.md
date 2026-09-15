# Nuclei Template: UEditor - Arbitrary File Upload
**Template ID:** ueditor-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** High
**CWE:** CWE-434
**Source:** Nuclei Template (`ueditor-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
UEditor contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ueditor/net/controller.ashx?action=catchimage&encode=utf-8
```

## References
- https://zhuanlan.zhihu.com/p/85265552
- https://www.freebuf.com/vuls/181814.html
