# Nuclei Template: Froxlor Server Management - Cross-Site Scripting
**Template ID:** froxlor-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`froxlor-xss.yaml`)

## Vulnerability Information & PoC

## Description
Froxlor Server Management is susceptible to cross-site scripting via clicking the forgot password link. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php/javascript%26colon%3Balert(document.domain);dd%26sol%3b%26sol%3b
```

