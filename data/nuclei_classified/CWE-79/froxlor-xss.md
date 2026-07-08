# Vulnerability: Froxlor Server Management - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`froxlor-xss.yaml`)

## Description
Froxlor Server Management is susceptible to cross-site scripting via clicking the forgot password link. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/javascript%26colon%3Balert(document.domain);dd%26sol%3b%26sol%3b
```

